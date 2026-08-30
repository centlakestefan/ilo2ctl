// power_control.hpp — RIBCL server control, off the UI thread.
//
// Every RIBCL call is a fresh TLS 1.0 handshake against a 1024-bit RSA iLO
// and then a reply that ends by timeout, so one call takes seconds. The UI
// cannot block on that, and two calls must not race the firmware, so this is
// a single worker that runs requests in order, polls the power state on its
// own while idle, and publishes results under a mutex for the frame loop to
// read whenever it likes.
#pragma once

#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <deque>
#include <mutex>
#include <string>
#include <thread>

#include "ilo/health.hpp"
#include "ilo/ribcl.hpp"

namespace ilo2 {

class PowerControl {
public:
    struct Config {
        std::string host;
        uint16_t    port = 443;
        std::string user;
        std::string pass;
        int         poll_sec = 10;      // status poll interval while idle; 0 = never
        int         health_sec = 30;    // health + wattage poll interval; 0 = never
    };

    struct Snapshot {
        std::string host_power;         // "ON" / "OFF" / "" (unknown)
        std::string last_action;        // name of the most recent command
        std::string last_result;        // its outcome, human-readable
        bool        busy = false;       // a request is in flight
        bool        error = false;      // last_result is an error
        HealthData    health;           // .valid once the first report is in
        PowerReadings watts;            // .valid once the first reading is in
    };

    ~PowerControl() { stop(); }

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

    void stop() {
        {
            std::lock_guard<std::mutex> lk(m_);
            run_ = false;
        }
        cv_.notify_all();
        if (thread_.joinable()) thread_.join();
    }

    bool running() const { return thread_.joinable(); }

    void request(RibclCommand cmd) {
        {
            std::lock_guard<std::mutex> lk(m_);
            queue_.push_back(cmd);
        }
        cv_.notify_all();
    }

    Snapshot snapshot() const {
        std::lock_guard<std::mutex> lk(m_);
        return snap_;
    }

private:
    void worker() {
        using clock = std::chrono::steady_clock;
        // First thing: learn the state, then the health.
        bool poll_due = true;
        clock::time_point last_health{};        // epoch: health is due immediately
        for (;;) {
            RibclCommand cmd;
            {
                std::unique_lock<std::mutex> lk(m_);
                const auto wait = std::chrono::seconds(cfg_.poll_sec > 0 ? cfg_.poll_sec : 3600);
                if (!poll_due) {
                    cv_.wait_for(lk, wait, [&] { return !run_ || !queue_.empty(); });
                }
                if (!run_) return;
                const bool health_due = cfg_.health_sec > 0 &&
                    clock::now() - last_health >= std::chrono::seconds(cfg_.health_sec);
                if (!queue_.empty()) {
                    cmd = queue_.front();
                    queue_.pop_front();
                } else if (poll_due || cfg_.poll_sec > 0) {
                    cmd = RibclCommand::GetPowerStatus;
                } else {
                    continue;
                }
                poll_due = false;
                // Health rides along after a status poll, as two extra reads.
                if (cmd == RibclCommand::GetPowerStatus && health_due) {
                    queue_.push_front(RibclCommand::GetPowerReadings);
                    queue_.push_front(RibclCommand::GetEmbeddedHealth);
                    last_health = clock::now();
                }
                snap_.busy = true;
                if (ribcl_is_write(cmd)) snap_.last_action = ribcl_command_name(cmd);
            }

            RibclReply reply;
            std::string err;
            const bool ok = ribcl_run(cfg_.host, cfg_.port, cfg_.user, cfg_.pass, cmd, reply, err);

            std::lock_guard<std::mutex> lk(m_);
            snap_.busy = false;
            if (!ok) {
                snap_.error = true;
                snap_.last_result = err;
                if (cmd == RibclCommand::GetPowerStatus) snap_.host_power.clear();
                continue;
            }
            if (!reply.host_power.empty()) snap_.host_power = reply.host_power;
            if (cmd == RibclCommand::GetEmbeddedHealth) {
                const HealthData h = parse_embedded_health(reply.raw);
                if (h.valid) snap_.health = h;
                continue;
            }
            if (cmd == RibclCommand::GetPowerReadings) {
                const PowerReadings p = parse_power_readings(reply.raw);
                if (p.valid) snap_.watts = p;
                continue;
            }
            if (ribcl_is_write(cmd)) {
                snap_.error = !reply.ok;
                snap_.last_result = reply.ok ? "ok" : (reply.message.empty() ? "failed" : reply.message);
                // A write changes the state; re-read it promptly rather than
                // waiting out the poll interval.
                poll_due = true;
            } else if (!reply.ok) {
                snap_.error = true;
                snap_.last_result = reply.message.empty() ? "status read failed" : reply.message;
            } else {
                snap_.error = false;
            }
        }
    }

    Config                  cfg_;
    std::thread             thread_;
    mutable std::mutex      m_;
    std::condition_variable cv_;
    std::deque<RibclCommand> queue_;
    Snapshot                snap_;
    bool                    run_ = false;
};

} // namespace ilo2
