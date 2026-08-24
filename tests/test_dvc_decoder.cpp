// test_dvc_decoder.cpp — equivalence test for dvc_decoder.hpp against the real
// cim FSM. Generates a deterministic byte stream (random bytes punctuated by
// zero-runs that trigger the reset marker, so the decoder keeps re-traversing
// the state tree instead of latching forever), writes it to
// build/decoder_stream.bin for the Java oracle to replay, feeds it through the
// C++ decoder, and snapshots the full decoder state after every byte.
#include <cstdio>
#include <cstdint>
#include <string>
#include "ilo/dvc_decoder.hpp"

using namespace ilo2;

class RecDecoder : public DvcDecoder {
public:
    std::string events;
    int pastes = 0, dims = 0, texts = 0;
protected:
    void on_paste(const int*, int x, int y, int len) override {
        events += "P " + std::to_string(x) + " " + std::to_string(y) + " " + std::to_string(len) + ";";
        ++pastes;
    }
    void on_set_dimensions(int w, int h) override {
        events += "D " + std::to_string(w) + " " + std::to_string(h) + ";"; ++dims;
    }
    void on_show_text(const std::string& s) override { events += "T " + s + ";"; ++texts; }
};

int main() {
    const int N = 20000;
    // xorshift32, fixed seed; punctuate with 5-byte zero-runs (reset markers).
    uint32_t x = 0x12345678u;
    std::string stream; stream.reserve(N);
    for (int i = 0; i < N; ++i) {
        uint8_t b;
        if (i % 16 < 5) b = 0;
        else { x ^= x << 13; x ^= x >> 17; x ^= x << 5; b = static_cast<uint8_t>(x); }
        stream.push_back(static_cast<char>(b));
    }
    if (FILE* f = std::fopen("build/decoder_stream.bin", "wb")) {
        std::fwrite(stream.data(), 1, stream.size(), f); std::fclose(f);
    } else { std::fprintf(stderr, "cannot write stream\n"); return 2; }

    RecDecoder d;
    FILE* snap = std::fopen("build/decoder_cpp.txt", "wb");
    if (!snap) { std::fprintf(stderr, "cannot write snapshot\n"); return 2; }

    for (int i = 0; i < N; ++i) {
        d.process_dvc(static_cast<uint8_t>(stream[i]));
        std::fprintf(snap,
            "%d %d %d %d %d %d %d %d %d %d %d %d %d %lld %d %d %d %d %d %d %d %d %lld %d %d %d %d\n",
            d.bits.decoder_state, d.bits.next_state, d.pixel_count, d.lastx, d.lasty,
            d.newx, d.newy, d.size_x, d.size_y, d.y_clipped, d.cache.cc_active,
            d.bits.ib_bcnt, d.bits.zero_count, (long long)d.count_bytes,
            d.video_detected ? 1 : 0, d.framerate, d.screen_x, d.screen_y, d.fatal_count,
            d.cmd_last, d.cmd_p_count, d.printchan, (long long)d.timeout_count,
            d.next_1_[31], d.pastes, d.dims, d.texts);
    }
    std::fclose(snap);

    if (FILE* ev = std::fopen("build/decoder_events_cpp.txt", "wb")) {
        std::fwrite(d.events.data(), 1, d.events.size(), ev); std::fclose(ev);
    }
    printf("fed %d bytes; pastes=%d dims=%d texts=%d\n", N, d.pastes, d.dims, d.texts);
    return 0;
}
