

#include "Data.hpp"

namespace Filter {
	namespace FilterFunction {
		extern CString Filter;
		extern bool IsFilterApply;
		extern CString DefaultFilterValue;

		BOOL CheckFilter(CString Filter, std::vector<CString> vec);
		BOOL FilterValidCheckFunction(CString Filter);
		int GetCountStr(CString target_str, CString target_find_str);
		std::vector<int> GetCountStrIdx(CString target_str, CString target_find_str);
		std::vector<CString> SplitStr(CString target_str, CString target_find_str);
	}
}