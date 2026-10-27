#pragma once
#include <memory>
#include <string>
#include <string_view>
#include <vector>

namespace dlp {

struct Match {
    size_t offset = 0;
    std::string masked;  // safe to log / send to cloud
};

// Detectors scan UTF-8 text. They are hand-written state machines rather than std::regex:
// std::regex backtracks recursively, is slow on multi-MB input and can overflow the stack.
class Detector {
public:
    virtual ~Detector() = default;
    virtual const std::string& name() const = 0;
    virtual void scan(std::string_view text, std::vector<Match>& out) const = 0;
};

// Built-in names: credit_card, tw_national_id, aws_access_key, github_token, email.
// Returns nullptr for an unknown name.
std::unique_ptr<Detector> make_builtin_detector(std::string_view name);

// Case-insensitive (ASCII) substring match on any of the keywords.
std::unique_ptr<Detector> make_keyword_detector(std::string name, std::vector<std::string> keywords);

bool luhn_valid(std::string_view digits);
bool tw_national_id_valid(std::string_view id);

// Keeps the first `head` and last `tail` characters, replaces the rest with '*'.
std::string mask(std::string_view value, size_t head, size_t tail);

}  // namespace dlp
