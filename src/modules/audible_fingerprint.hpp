#pragma once

#include <algorithm>
#include <array>
#include <cmath>
#include <cstdint>
#include <string>
#include <vector>

namespace pqvpn::audible {

// This is a human-friendly sonification, never a cryptographic verifier.  The
// authenticated public identity remains the Ed25519 + ML-DSA-87 wallet proof.
struct FingerprintMelody {
    std::array<int, 8> midi{};

    [[nodiscard]] std::string notation() const {
        static constexpr std::array<const char*, 12> names{
            "C", "C#", "D", "D#", "E", "F", "F#", "G", "G#", "A", "A#", "B"};
        std::string result;
        for (std::size_t i = 0; i < midi.size(); ++i) {
            if (i) result += " · ";
            result += names[static_cast<std::size_t>(midi[i] % 12)];
            result += std::to_string(midi[i] / 12 - 1);
        }
        return result;
    }
};

[[nodiscard]] inline FingerprintMelody from_public_identity(const std::string& identity) {
    // Stable FNV-1a based mixing is sufficient for melody selection.  It is
    // deliberately not presented as a cryptographic digest or collision proof.
    std::uint64_t state = 14695981039346656037ULL;
    for (const unsigned char value : identity) {
        state ^= value;
        state *= 1099511628211ULL;
    }
    static constexpr std::array<int, 15> scale{
        48, 50, 52, 55, 57, 60, 62, 64, 67, 69, 72, 74, 76, 79, 81};
    FingerprintMelody melody;
    for (std::size_t i = 0; i < melody.midi.size(); ++i) {
        state ^= state >> 12;
        state ^= state << 25;
        state ^= state >> 27;
        state *= 2685821657736338717ULL;
        melody.midi[i] = scale[static_cast<std::size_t>(state % scale.size())];
    }
    return melody;
}

[[nodiscard]] inline std::vector<std::int16_t> synthesize(
    const FingerprintMelody& melody, int sample_rate = 16000,
    int note_ms = 115, double gain = 0.18) {
    sample_rate = std::clamp(sample_rate, 8000, 48000);
    note_ms = std::clamp(note_ms, 60, 250);
    gain = std::clamp(gain, 0.0, 0.25);
    const int samples_per_note = sample_rate * note_ms / 1000;
    std::vector<std::int16_t> pcm;
    pcm.reserve(melody.midi.size() * static_cast<std::size_t>(samples_per_note));
    constexpr double pi = 3.14159265358979323846;
    for (const int midi : melody.midi) {
        const double frequency = 440.0 * std::pow(2.0, (midi - 69) / 12.0);
        for (int sample = 0; sample < samples_per_note; ++sample) {
            const double phase = 2.0 * pi * frequency * sample / sample_rate;
            const double edge = std::min(sample, samples_per_note - 1 - sample);
            const double envelope = std::clamp(edge / (sample_rate * 0.012), 0.0, 1.0);
            const double tone = std::sin(phase) + 0.18 * std::sin(phase * 2.0);
            pcm.push_back(static_cast<std::int16_t>(tone * envelope * gain * 32767.0 / 1.18));
        }
    }
    return pcm;
}

} // namespace pqvpn::audible
