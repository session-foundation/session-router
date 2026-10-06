#pragma once

#include <filesystem>
#include <functional>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

namespace srouter
{
    struct ConfigParser
    {
        explicit ConfigParser(std::string file_description) : _file_desc{std::move(file_description)} {}

        using SectionValues = std::unordered_map<std::string, std::vector<std::string>>;
        using ConfigMap = std::unordered_map<std::string, SectionValues>;

        /// clear parser
        void clear();

        /// Load config file.  Throws on error.
        void load_file(const std::filesystem::path& fname);

        /// Load from string. Throws on error.
        void load_from_str(std::string str);

        /// iterate all sections and thier values
        void iter_all_sections(std::function<void(std::string_view, const SectionValues&)> visit);

        /// visit a section in config read only by name
        /// return false if no section or value propagated from visitor
        bool visit_section(const char* name, std::function<bool(const SectionValues&)> visit) const;

      private:
        void parse_all();

        void parse();

        std::string _data;
        ConfigMap _config;
        std::string _file_desc;
    };

}  // namespace srouter
