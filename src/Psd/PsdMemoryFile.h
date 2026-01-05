// Copyright 2011-2020, Molecular Matters GmbH <office@molecular-matters.com>
// See LICENSE.txt for licensing details (2-clause BSD License: https://opensource.org/licenses/BSD-2-Clause)

#pragma once

#include "PsdFile.h"


PSD_NAMESPACE_BEGIN

/// \ingroup Files
/// \brief Simple file implementation backed by memory.
/// \details This class presents an in-memory buffer through the \ref File interface which makes it possible to reuse
/// parsing routines that expect a File, e.g. \ref CreateDocument.
class MemoryFile : public File
{
public:
	/// Constructor.
	explicit MemoryFile(Allocator* allocator);

	/// Attaches this file view to a memory region, enabling subsequent read operations.
	bool Open(const void* data, uint64_t size);

private:
	virtual bool DoOpenRead(const wchar_t* filename) PSD_OVERRIDE;
	virtual bool DoOpenWrite(const wchar_t* filename) PSD_OVERRIDE;
	virtual bool DoClose(void) PSD_OVERRIDE;

	virtual File::ReadOperation DoRead(void* buffer, uint32_t count, uint64_t position) PSD_OVERRIDE;
	virtual bool DoWaitForRead(File::ReadOperation& operation) PSD_OVERRIDE;

	virtual File::WriteOperation DoWrite(const void* buffer, uint32_t count, uint64_t position) PSD_OVERRIDE;
	virtual bool DoWaitForWrite(File::WriteOperation& operation) PSD_OVERRIDE;

	virtual uint64_t DoGetSize(void) const PSD_OVERRIDE;

	const uint8_t* m_data;
	uint64_t m_size;
	bool m_isOpen;
};

PSD_NAMESPACE_END

