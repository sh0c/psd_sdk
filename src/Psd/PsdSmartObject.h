// Copyright 2011-2020, Molecular Matters GmbH <office@molecular-matters.com>
// See LICENSE.txt for licensing details (2-clause BSD License: https://opensource.org/licenses/BSD-2-Clause)

#pragma once


PSD_NAMESPACE_BEGIN

class MemoryFile;

/// \ingroup Types
/// \class SmartObject
/// \brief A struct representing raw smart object data stored as Additional Layer Information.
struct SmartObject
{
	uint64_t fileOffset;			///< Offset of the smart object data block relative to the beginning of the file.
	uint64_t size;					///< Size of the stored smart object data in bytes.
	void* data;						///< Raw smart object data.
	MemoryFile* file;				///< Memory-backed file allowing to re-parse the smart object via CreateDocument().
	uint32_t fileType;				///< Type of the embedded file (e.g. '8BPS', 'png ').
};

PSD_NAMESPACE_END
