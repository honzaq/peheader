#pragma once

#include <stdint.h>
#include <set>
#include <map>
#include <vector>
#include <string>
#include <sstream>

namespace cmdp
{

namespace comparator {
	struct compare_no_case : public std::binary_function<std::wstring, std::wstring, bool> {
		bool operator()(const std::wstring& lhs, const std::wstring& rhs) const {
			return _wcsicmp(lhs.c_str(), rhs.c_str()) < 0;
		}
	};
}

class parser
{
public:
	//////////////////////////////////////////////////////////////////////////////////////////
	// Defines
	enum parse_mode : int32_t {
		NONE  = 1 << 0,
	};
	struct value_data {
		bool has_value = false;
		std::wstring value;
	};
	typedef std::map<std::wstring, value_data, comparator::compare_no_case> params_map;
	
public:
	parser() = default;
	parser(int argc, const wchar_t* const argv[], parse_mode mode = NONE);

	void parse(int argc, const wchar_t* const argv[], parse_mode mode = NONE);

	params_map const& params() const {
		return m_params;
	}

public:
	//////////////////////////////////////////////////////////////////////////////////////////
	// Accessors

	// param/flag (boolean) accessors: return true if the flag appeared, otherwise false.
	bool operator[](const std::wstring& name);
	// param value accessor
	std::wistringstream operator()(const std::wstring& name);

private:
	void parse_one_param(const wchar_t* const param, std::wstring& prev_param_name);
	inline std::wistringstream parser::bad_stream() const;

private:
	params_map m_params;
};

////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// IMPLEMENTATION
////////////////////////////////////////////////////////////////////////////////////////////////////////////////

parser::parser(int argc, const wchar_t* const argv[], parse_mode mode /*= PREFER_FLAG_FOR_UNREG_OPTION*/)
{
	parse(argc, argv, mode);
}

void parser::parse(int argc, const wchar_t* const argv[], parse_mode /*mode = PREFER_FLAG_FOR_UNREG_OPTION*/)
{
/*
 * -flag
 * --flag
 * /flag
 * /param=<param_value> (do not allow spaces between param and '=')
 * -param=<param_value>
 * --param=<param_value>
 * /param:<param_value>
 * -param:<param_value>
 *
 * /param <param_value> (next argv)
 * -param <param_value> (next argv)
 *
 * <param_value>:
 *   text_without_spaces 
 *   "text with spaces, \" is not end, end with "
 * ignore spaces+tabs on beginning
 */

	std::wstring prev_param_name;
	for (auto i = 0; i < argc; ++i) {
		parse_one_param(argv[i], prev_param_name);
	}
}

bool parser::operator[](const std::wstring& name)
{
	return m_params.find(name) != m_params.end();
}

std::wistringstream parser::operator()(const std::wstring& name)
{
	if (name.empty()) {
		return bad_stream();
	}

	const auto& param = m_params.find(name);
	if (param == m_params.end()) {
		return bad_stream();
	}

	if (!param->second.has_value) {
		return bad_stream();
	}

	return std::wistringstream(param->second.value);
}

void parser::parse_one_param(const wchar_t* const param, std::wstring& prev_param_name)
{
	enum States {
		none,
		flag_detect,
		flag_read,
		param_value_detect,
		param_value_read,
		param_value_read_escaped,
		param_value_quoted_detect,
		param_value_quoted_read,
		param_value_quoted_read_escaped,
	};

	States state = none;
	size_t len = wcslen(param);

	std::wstring param_name;
	value_data new_value;

	for (size_t i = 0; i < len; ++i) {

		switch (state)
		{
		case none:
			if (param[i] == ' ' || param[i] == '\t') {
				continue;
			}
			else if (param[i] == '-' || param[i] == '/') {
				state = flag_detect;
				continue;
			}
			// param, this 
			else if ((param[i] >= 'a' && param[i] <= 'z') || (param[i] >= '0' && param[i] <= '9') || (param[i] >= 'A' && param[i] <= 'Z')) {
				new_value.value += param[i];
				state = param_value_read;
			}
			else if (param[i] == '"') {
				state = param_value_quoted_detect;
			}
			else if (param[i] == '\\') {
				state = param_value_read_escaped;
			}
			else {
				continue; // not value
			}
			new_value.has_value = true;
			continue;
			// end param
			break;
		case flag_detect:
			if (param[i] == '-') {
				state = flag_read;
				continue;
			}
			else if ((param[i] >= 'a' && param[i] <= 'z') || (param[i] >= '0' && param[i] <= '9') || (param[i] >= 'A' && param[i] <= 'Z')) {
				param_name += param[i];
				state = flag_read;
				continue;
			}
			else {
				state = none;
				continue;
			}
			break;
		case flag_read:
			if ((param[i] >= 'a' && param[i] <= 'z') || (param[i] >= '0' && param[i] <= '9') || (param[i] >= 'A' && param[i] <= 'Z') || param[i] == '-' || param[i] == '_') {
				param_name += param[i];
				continue;
			}
			else if (param[i] == '=' || param[i] == ':') {
				state = param_value_detect;
				new_value.has_value = true;
				continue;
			}
			else {
				state = none;
				break; // invalid break
			}
			break;
		case param_value_detect:
			if ((param[i] >= 'a' && param[i] <= 'z') || (param[i] >= '0' && param[i] <= '9') || (param[i] >= 'A' && param[i] <= 'Z')) {
				new_value.value += param[i];
				state = param_value_read;
				continue;
			}
			else if (param[i] == '"') {
				state = param_value_quoted_detect;
				continue;
			}
			else if (param[i] == '\\') {
				state = param_value_read_escaped;
				continue;
			}
			else {
				state = none;
				break; // invalid break
			}
			break;
		case param_value_read_escaped:
			if (param[i] == 't') new_value.value += '\t';
			else if (param[i] == '\\') new_value.value += '\\';
			else if (param[i] == '"') new_value.value += '\"';
			state = param_value_read;
			continue;
			break;
		case param_value_read:
			new_value.value += param[i];
			continue;
			break;
		case param_value_quoted_detect:
			if (param[i] == '\\') {
				state = param_value_quoted_read_escaped;
				continue;
			}
			else if (param[i] == '"') {
				// Store whole param
				state = none;
				continue;
			}
			else {
				new_value.value += param[i];
				state = param_value_quoted_read;
				continue;
			}
			break;
		case param_value_quoted_read_escaped:
			if (param[i] == 't') new_value.value += '\t';
			else if (param[i] == '\\') new_value.value += '\\';
			else if (param[i] == '"') new_value.value += '\"';
			state = param_value_quoted_read;
			continue;
			break;

		case param_value_quoted_read:
			if (param[i] == '\\') {
				state = param_value_quoted_read_escaped;
				continue;
			}
			else if (param[i] == '"') {
				state = none;
				continue;
			}
			else {
				new_value.value += param[i];
				continue;
			}
			break;
		} // end of switch
	}

	if (!param_name.empty()) {
		m_params.insert({ param_name, new_value });

		// We do not have param, maybe next time
		if (!new_value.has_value) {
			prev_param_name.swap(param_name);
		}
	}
	else if(!prev_param_name.empty()) {
		if (new_value.has_value) {
			m_params[prev_param_name] = new_value;
		}
		prev_param_name.clear();
	}
}

inline std::wistringstream parser::bad_stream() const
{
	std::wistringstream bad;
	bad.setstate(std::ios_base::failbit);
	return bad;
}

} // End of namespace cmdp