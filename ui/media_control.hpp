// media_control.hpp — virtual media, off the UI thread.
//
// The sibling of power_control.hpp, and the same shape for the same reason:
// every RIBCL call is a fresh TLS 1.0 handshake against a 1024-bit iLO, so one
// takes seconds and the UI cannot block on it. A single worker runs requests in
// order, polls the media state while idle, and publishes results under a mutex.
//
// It owns the HTTP server too, because the two have one lifetime between them:
// the firmware reads the image for as long as it is mounted, so stopping the
// server out from under a running install would break it. Ejecting stops the
// server; stopping the worker ejects.
//
// Deliberately split into two steps, rather than one "mount and boot" button:
//
//   mount(iso)  starts the server and inserts the image. It changes no boot
//               setting, so it cannot cause a reboot to land somewhere
//               unexpected, and it is safe against a running host.
//   arm_boot()  sets BOOT_ONCE and one-time boot to CDROM. This *does* change
//               what the next reboot does, which is why it is its own call for
//               a front end to guard behind a confirmation.
//
// Two firmware behaviours drove that split, both recorded in
// testdata/README.md: INSERT_VIRTUAL_MEDIA fetches nothing (only connecting the
// device makes the firmware open the URL), and VM_BOOT_OPTION CONNECT silently
// sets BOOT_ALWAYS -- so "just connect it" is not the harmless-sounding thing
// it appears to be.
#pragma once

#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <deque>
#include <mutex>
#include <string>
#include <thread>

#include "ilo/media_server.hpp"
#include "ilo/ribcl.hpp"
#include "tls/socket.hpp"

namespace ilo2 {

class MediaControl {
public:
    struct Config {
        std::string host;
        uint16_t    port = 443;         // iLO RIBCL
        std::string user;
        std::string pass;
        uint16_t    http_port = 8080;   // where we serve the image
        int         poll_sec = 15;      // media-state poll while idle; 0 = never
    };

    struct Snapshot {
        VmStatus     vm;                // .valid once the first read is in
        FwInfo       fw;                // .valid once known; carries the licence
        MediaServer::Stats server;      // .running, requests, bytes
        std::string  url;               // what the iLO was given, if anything
        std::string  iso;               // local path being served
        std::string  last_action;
        std::string  last_result;
        bool         busy  = false;
        bool         error = false;
        bool         boot_armed = false;  // arm_boot() succeeded since the last mount
    };

    ~MediaControl() { stop(); }

    void start(const Config& cfg) {
        stop();
        cfg_ = cfg;
        run_ = true;
        {
            std::lock_guard<std::mutex> lk(m_);
            snap_ = Snapshot();
            queue_.clear();
        }
        thread_ = std::thread([this] { worker(); });
    }

    // Ejects and stops serving before returning: leaving an iLO pointed at a
    // URL that has stopped answering is worse than not having mounted at all.
    void stop() {
        {
            std::lock_guard<std::mutex> lk(m_);
            run_ = false;
        }
        cv_.notify_all();
        if (thread_.joinable()) thread_.join();
        server_.stop();
    }

    bool running() const { return thread_.joinable(); }

    void mount(const std::string& iso_path) { push(Job{Job::Mount, iso_path}); }
    void eject()                            { push(Job{Job::Eject, {}}); }
    void arm_boot()                         { push(Job{Job::ArmBoot, {}}); }
    void refresh()                          { push(Job{Job::Refresh, {}}); }

    Snapshot snapshot() const {
        std::lock_guard<std::mutex> lk(m_);
        Snapshot s = snap_;
        s.server = server_.stats();     // live, not a copy from the last poll
        return s;
    }

private:
    struct Job {
        enum Kind { Mount, Eject, ArmBoot, Refresh } kind;
        std::string arg;
    };

    void push(Job j) {
        {
            std::lock_guard<std::mutex> lk(m_);
            queue_.push_back(std::move(j));
        }
        cv_.notify_all();
    }

    // One RIBCL round trip, reporting into the snapshot. Returns the reply so
    // callers can parse it further.
    bool run(RibclCommand cmd, const RibclArgs& args, RibclReply& reply) {
        {
            std::lock_guard<std::mutex> lk(m_);
            snap_.busy = true;
            if (ribcl_is_write(cmd)) snap_.last_action = ribcl_command_name(cmd);
        }
        std::string err;
        const bool ok = ribcl_run(cfg_.host, cfg_.port, cfg_.user, cfg_.pass,
                                  cmd, args, reply, err);
        std::lock_guard<std::mutex> lk(m_);
        snap_.busy = false;
        if (!ok) {
            snap_.error = true;
            snap_.last_result = err;
            return false;
        }
        if (!reply.ok) {
            snap_.error = true;
            snap_.last_result = reply.message.empty() ? "command failed" : reply.message;
            return false;
        }
        snap_.error = false;
        if (ribcl_is_write(cmd)) snap_.last_result = "ok";
        return true;
    }

    void read_status() {
        RibclReply r;
        if (!run(RibclCommand::GetVmStatus, RibclArgs{}, r)) return;
        const VmStatus v = parse_vm_status(r.raw);
        std::lock_guard<std::mutex> lk(m_);
        if (v.valid) snap_.vm = v;
    }

    void read_fw() {
        RibclReply r;
        if (!run(RibclCommand::GetFwVersion, RibclArgs{}, r)) return;
        const FwInfo f = parse_fw_version(r.raw);
        std::lock_guard<std::mutex> lk(m_);
        if (f.valid) snap_.fw = f;
    }

    void do_mount(const std::string& iso) {
        // Refuse early on a base licence rather than after starting a server
        // and failing at insert with a firmware error nobody can act on.
        {
            std::lock_guard<std::mutex> lk(m_);
            if (snap_.fw.valid && !vm_scripting_licensed(snap_.fw)) {
                snap_.error = true;
                snap_.last_result = "this iLO's licence (" + snap_.fw.license_type +
                                    ") does not allow scripted virtual media";
                return;
            }
        }

        std::string err;
        if (!server_.start(iso, cfg_.http_port, err)) {
            std::lock_guard<std::mutex> lk(m_);
            snap_.error = true;
            snap_.last_result = err;
            return;
        }

        const std::string local = net::local_address_towards(cfg_.host, cfg_.port);
        if (local.empty()) {
            server_.stop();
            std::lock_guard<std::mutex> lk(m_);
            snap_.error = true;
            snap_.last_result = "cannot determine which local address reaches " + cfg_.host;
            return;
        }
        const std::string url = server_.url(local);

        RibclArgs a;
        a.image_url = url;
        RibclReply r;
        if (!run(RibclCommand::InsertVirtualMedia, a, r)) {
            server_.stop();                 // nothing is mounted; do not keep serving
            return;
        }
        {
            std::lock_guard<std::mutex> lk(m_);
            snap_.url = url;
            snap_.iso = iso;
            snap_.boot_armed = false;       // a fresh image is not armed
        }
        read_status();
    }

    void do_eject() {
        RibclReply r;
        run(RibclCommand::EjectVirtualMedia, RibclArgs{}, r);
        server_.stop();                     // whether or not the eject succeeded
        {
            std::lock_guard<std::mutex> lk(m_);
            snap_.url.clear();
            snap_.iso.clear();
            snap_.boot_armed = false;
        }
        read_status();
    }

    // BOOT_ONCE plus one-time boot to CDROM. Both of these arm the next reboot,
    // and neither has been exercised against hardware -- see the
    // verified/unverified split in testdata/README.md.
    void do_arm_boot() {
        RibclArgs vm;
        vm.boot_option = "BOOT_ONCE";
        RibclReply r;
        if (!run(RibclCommand::SetVmBootOption, vm, r)) return;

        RibclArgs ot;
        ot.boot_device = "CDROM";
        if (!run(RibclCommand::SetOneTimeBoot, ot, r)) return;
        {
            std::lock_guard<std::mutex> lk(m_);
            snap_.boot_armed = true;
        }
        read_status();
    }

    void worker() {
        using clock = std::chrono::steady_clock;
        read_fw();              // the licence gates everything else
        read_status();
        clock::time_point last_poll = clock::now();

        for (;;) {
            Job job;
            bool have_job = false;
            {
                std::unique_lock<std::mutex> lk(m_);
                const auto wait = std::chrono::seconds(cfg_.poll_sec > 0 ? cfg_.poll_sec : 3600);
                cv_.wait_for(lk, wait, [&] { return !run_ || !queue_.empty(); });
                if (!run_) break;
                if (!queue_.empty()) {
                    job = std::move(queue_.front());
                    queue_.pop_front();
                    have_job = true;
                }
            }

            if (have_job) {
                switch (job.kind) {
                    case Job::Mount:   do_mount(job.arg); break;
                    case Job::Eject:   do_eject();        break;
                    case Job::ArmBoot: do_arm_boot();     break;
                    case Job::Refresh: read_status();     break;
                }
                last_poll = clock::now();
                continue;
            }

            if (cfg_.poll_sec > 0 &&
                clock::now() - last_poll >= std::chrono::seconds(cfg_.poll_sec)) {
                read_status();
                last_poll = clock::now();
            }
        }

        // Shutting down with an image still mounted would leave the iLO
        // pointed at a server about to disappear.
        bool mounted;
        {
            std::lock_guard<std::mutex> lk(m_);
            mounted = !snap_.url.empty();
        }
        if (mounted) {
            RibclReply r;
            run(RibclCommand::EjectVirtualMedia, RibclArgs{}, r);
        }
        server_.stop();
    }

    Config                  cfg_;
    MediaServer             server_;
    std::thread             thread_;
    mutable std::mutex      m_;
    std::condition_variable cv_;
    std::deque<Job>         queue_;
    Snapshot                snap_;
    bool                    run_ = false;
};

} // namespace ilo2
