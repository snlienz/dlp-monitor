#include "agent/detectors.h"

#include <algorithm>
#include <array>

namespace dlp {
namespace {

bool is_digit(char c) { return c >= '0' && c <= '9'; }
bool is_upper(char c) { return c >= 'A' && c <= 'Z'; }
bool is_alnum(char c) { return is_digit(c) || is_upper(c) || (c >= 'a' && c <= 'z'); }
char ascii_lower(char c) { return (c >= 'A' && c <= 'Z') ? static_cast<char>(c - 'A' + 'a') : c; }

// True when position i is not glued to a neighbouring alphanumeric character.
bool word_start(std::string_view t, size_t i) { return i == 0 || !is_alnum(t[i - 1]); }
bool word_end(std::string_view t, size_t i) { return i >= t.size() || !is_alnum(t[i]); }

class CreditCardDetector final : public Detector {
public:
    const std::string& name() const override { return name_; }

    void scan(std::string_view t, std::vector<Match>& out) const override {
        size_t i = 0;
        while (i < t.size()) {
            if (!is_digit(t[i]) || !word_start(t, i)) {
                ++i;
                continue;
            }
            // Collect up to 19 digits, allowing single ' ' or '-' separators between groups.
            std::string digits;
            size_t j = i;
            while (j < t.size() && digits.size() < 19) {
                if (is_digit(t[j])) {
                    digits.push_back(t[j]);
                    ++j;
                } else if ((t[j] == ' ' || t[j] == '-') && j + 1 < t.size() && is_digit(t[j + 1])) {
                    ++j;
                } else {
                    break;
                }
            }
            if (digits.size() >= 13 && word_end(t, j) && plausible_prefix(digits) &&
                luhn_valid(digits)) {
                out.push_back({i, mask(digits, 0, 4)});
                i = j;
            } else {
                // Skip the rest of this token so we don't rescan every suffix of a long number.
                while (i < t.size() && is_alnum(t[i])) ++i;
            }
        }
    }

private:
    static bool plausible_prefix(const std::string& d) {
        // Visa 4, Mastercard 5/2, Amex/Diners/JCB 3, Discover/UnionPay 6.
        return d[0] == '4' || d[0] == '5' || d[0] == '2' || d[0] == '3' || d[0] == '6';
    }
    std::string name_ = "credit_card";
};

class TwNationalIdDetector final : public Detector {
public:
    const std::string& name() const override { return name_; }

    void scan(std::string_view t, std::vector<Match>& out) const override {
        for (size_t i = 0; i + 10 <= t.size(); ++i) {
            if (!is_upper(t[i]) || !word_start(t, i) || !word_end(t, i + 10)) continue;
            const auto candidate = t.substr(i, 10);
            if (tw_national_id_valid(candidate)) {
                out.push_back({i, mask(candidate, 1, 2)});
                i += 9;
            }
        }
    }

private:
    std::string name_ = "tw_national_id";
};

// Fixed prefix followed by a fixed-length run of allowed characters.
class PrefixTokenDetector final : public Detector {
public:
    PrefixTokenDetector(std::string name, std::string prefix, size_t body_len, bool (*allowed)(char))
        : name_(std::move(name)), prefix_(std::move(prefix)), body_len_(body_len), allowed_(allowed) {}

    const std::string& name() const override { return name_; }

    void scan(std::string_view t, std::vector<Match>& out) const override {
        const size_t total = prefix_.size() + body_len_;
        size_t i = 0;
        while ((i = t.find(prefix_, i)) != std::string_view::npos) {
            const bool ok = i + total <= t.size() && word_start(t, i) && word_end(t, i + total) &&
                            std::all_of(t.begin() + static_cast<std::ptrdiff_t>(i + prefix_.size()),
                                        t.begin() + static_cast<std::ptrdiff_t>(i + total), allowed_);
            if (ok) {
                out.push_back({i, mask(t.substr(i, total), prefix_.size(), 4)});
                i += total;
            } else {
                i += prefix_.size();
            }
        }
    }

private:
    std::string name_;
    std::string prefix_;
    size_t body_len_;
    bool (*allowed_)(char);
};

class EmailDetector final : public Detector {
public:
    const std::string& name() const override { return name_; }

    void scan(std::string_view t, std::vector<Match>& out) const override {
        size_t at = 0;
        while ((at = t.find('@', at)) != std::string_view::npos) {
            size_t b = at;
            while (b > 0 && is_local(t[b - 1])) --b;
            size_t e = at + 1;
            while (e < t.size() && (is_alnum(t[e]) || t[e] == '-' || t[e] == '.')) ++e;
            while (e > at + 1 && t[e - 1] == '.') --e;  // "write to a@b.com." ends the sentence

            const auto domain = t.substr(at + 1, e - at - 1);
            const size_t dot = domain.rfind('.');
            const bool ok = b < at && dot != std::string_view::npos && dot > 0 &&
                            domain.size() - dot - 1 >= 2;
            if (ok) {
                out.push_back({b, mask(t.substr(b, at - b), 1, 0) + std::string(t.substr(at, e - at))});
                at = e;
            } else {
                at += 1;
            }
        }
    }

private:
    static bool is_local(char c) {
        return is_alnum(c) || c == '.' || c == '_' || c == '%' || c == '+' || c == '-';
    }
    std::string name_ = "email";
};

class KeywordDetector final : public Detector {
public:
    KeywordDetector(std::string name, std::vector<std::string> keywords) : name_(std::move(name)) {
        for (auto& k : keywords) {
            if (k.empty()) continue;
            std::transform(k.begin(), k.end(), k.begin(), ascii_lower);
            keywords_.push_back(std::move(k));
        }
    }

    const std::string& name() const override { return name_; }

    void scan(std::string_view t, std::vector<Match>& out) const override {
        std::string lower(t);
        std::transform(lower.begin(), lower.end(), lower.begin(), ascii_lower);
        for (const auto& k : keywords_) {
            for (size_t i = lower.find(k); i != std::string::npos; i = lower.find(k, i + k.size()))
                out.push_back({i, k});
        }
    }

private:
    std::string name_;
    std::vector<std::string> keywords_;
};

bool aws_body_char(char c) { return is_digit(c) || is_upper(c); }
bool github_body_char(char c) { return is_alnum(c); }

}  // namespace

bool luhn_valid(std::string_view digits) {
    int sum = 0;
    bool dbl = false;
    for (auto it = digits.rbegin(); it != digits.rend(); ++it) {
        if (!is_digit(*it)) return false;
        int d = *it - '0';
        if (dbl) {
            d *= 2;
            if (d > 9) d -= 9;
        }
        sum += d;
        dbl = !dbl;
    }
    return !digits.empty() && sum % 10 == 0;
}

bool tw_national_id_valid(std::string_view id) {
    // Letter -> area code. I, O, W..Z are out of alphabetical order for historical reasons.
    static constexpr std::array<int, 26> kArea{10, 11, 12, 13, 14, 15, 16, 17, 34, 18, 19, 20, 21,
                                               22, 35, 23, 24, 25, 26, 27, 28, 29, 32, 30, 31, 33};
    if (id.size() != 10 || !is_upper(id[0])) return false;
    // Second char: 1/2 = citizen gender, 8/9 = new-format resident certificate.
    if (id[1] != '1' && id[1] != '2' && id[1] != '8' && id[1] != '9') return false;
    for (size_t i = 1; i < 10; ++i)
        if (!is_digit(id[i])) return false;

    const int area = kArea[static_cast<size_t>(id[0] - 'A')];
    int sum = area / 10 + (area % 10) * 9;
    for (size_t i = 1; i <= 8; ++i) sum += (id[i] - '0') * static_cast<int>(9 - i);
    sum += id[9] - '0';
    return sum % 10 == 0;
}

std::string mask(std::string_view value, size_t head, size_t tail) {
    if (head + tail >= value.size()) return std::string(value.size(), '*');
    std::string out(value);
    std::fill(out.begin() + static_cast<std::ptrdiff_t>(head),
              out.end() - static_cast<std::ptrdiff_t>(tail), '*');
    return out;
}

std::unique_ptr<Detector> make_builtin_detector(std::string_view name) {
    if (name == "credit_card") return std::make_unique<CreditCardDetector>();
    if (name == "tw_national_id") return std::make_unique<TwNationalIdDetector>();
    if (name == "aws_access_key")
        return std::make_unique<PrefixTokenDetector>("aws_access_key", "AKIA", 16, aws_body_char);
    if (name == "github_token")
        return std::make_unique<PrefixTokenDetector>("github_token", "ghp_", 36, github_body_char);
    if (name == "email") return std::make_unique<EmailDetector>();
    return nullptr;
}

std::unique_ptr<Detector> make_keyword_detector(std::string name, std::vector<std::string> keywords) {
    return std::make_unique<KeywordDetector>(std::move(name), std::move(keywords));
}

}  // namespace dlp
