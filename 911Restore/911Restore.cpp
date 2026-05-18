#include "pch.h"
#include "helper.hpp"
//#include "mgs2.h"


// Thanks Afevis and SolidSnake11 for explaining these
typedef struct {
	unsigned long long class_id;
	void* (*init)(int, int);
} CHARA;

typedef struct {
	char* name;
	CHARA* funcs;
} StageFuncTableMapping;

// Globals
StageFuncTableMapping* g_stageFuncsTable;

// must be sorted by class_id
std::vector<CHARA> neededCharas = { {0xA895C4, nullptr} };

static std::vector<std::pair<const char*, std::vector<int>>> funcsToAdd = {
	// Uses indices in "neededCharas"
	// TODO: predefined list so this doesn't need to iterate to match names?
	{ "w61a", {0} },
	{ "a61a", {0} },
	{ "d080p08", {0} },
	{ "d082p01", {0} }
};
// Init to same size (TODO: not doing that)
std::vector<std::pair<CHARA**, CHARA*>> newTables = {
	{nullptr, nullptr},
	{nullptr, nullptr},
	{nullptr, nullptr},
	{nullptr, nullptr}
};


// Run on mod initialization (set hooks etc)
void Mod() {
	// ===== gcx function table expansion =====
	g_stageFuncsTable = (StageFuncTableMapping*)Memory::GetRelativeOffset(Memory::PatternScan(baseModule, "48 83 EC 28 E8 ?? ?? ?? ?? 48 8B 0D ?? ?? ?? ?? 4C 8D 0D") + 12);

	if (!g_stageFuncsTable) {
		return;
	}

	for (int i = 0; g_stageFuncsTable[i].funcs; i++) {
		// Get function pointers for neededCharas
		CHARA* funcs = g_stageFuncsTable[i].funcs;
		for (int j = 0; funcs[j].init; j++) {
			for (int k = 0; k < neededCharas.size(); k++) {
				if (funcs[j].class_id == neededCharas[k].class_id) {
					neededCharas[k].init = funcs[j].init;
				}
			}
		}

		// Initialize tables to copy
		for (int k = 0; k < funcsToAdd.size(); k++) {
			if (!strcmp(funcsToAdd[k].first, g_stageFuncsTable[i].name)) {
				long long j = 0;
				while (funcs[j].init && funcs[j].class_id) j++;

				newTables[k].first = &g_stageFuncsTable[i].funcs;
				newTables[k].second = (CHARA*)malloc(sizeof(CHARA) * (j + 1 + funcsToAdd[k].second.size()));
				/*newTables.push_back({
					&g_stageFuncsTable[i].funcs,
					(CHARA*)malloc(sizeof(CHARA) * (j + 1 + funcsToAdd[k].second.size()))
				});*/
			}
		}
	}

	// Insert copies
	for (int i = 0; i < funcsToAdd.size(); i++) {
		CHARA* oldTable = *newTables[i].first;
		CHARA* newTable = newTables[i].second;
		int j, k = 0;
		int funcToInsertInd = 0;
		for (j = 0; oldTable[k].init; j++) {
			newTable[j] = oldTable[k];
			if (funcToInsertInd < funcsToAdd[i].second.size() && neededCharas[funcToInsertInd].class_id < newTable[j].class_id) {
				// Insert new function here (do not increment k so what was just set will still be set on the next iteration)
				newTable[j] = neededCharas[funcToInsertInd];
				funcToInsertInd++;
			}
			else
				k++;
		}
		// Null terminator
		newTable[j].class_id = 0;
		newTable[j].init = nullptr;
		// Insert new table into meta-table
		*newTables[i].first = newTables[i].second;
	}
	// ===== end gcx function table expansion =====
}