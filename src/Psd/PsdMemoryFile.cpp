// Copyright 2011-2020, Molecular Matters GmbH <office@molecular-matters.com>
// See LICENSE.txt for licensing details (2-clause BSD License: https://opensource.org/licenses/BSD-2-Clause)

#include "PsdPch.h"
#include "PsdMemoryFile.h"

#include "PsdAllocator.h"
#include "PsdAssert.h"
#include "PsdCompilerMacros.h"
#include <cstring>


PSD_NAMESPACE_BEGIN

// ---------------------------------------------------------------------------------------------------------------------
// ---------------------------------------------------------------------------------------------------------------------
MemoryFile::MemoryFile(Allocator* allocator)
	: File(allocator)
	, m_data(nullptr)
	, m_size(0u)
	, m_isOpen(false)
{
}


// ---------------------------------------------------------------------------------------------------------------------
// ---------------------------------------------------------------------------------------------------------------------
bool MemoryFile::Open(const void* data, uint64_t size)
{
	PSD_ASSERT_NOT_NULL(data);

	m_data = static_cast<const uint8_t*>(data);
	m_size = size;
	m_isOpen = true;
	return true;
}


// ---------------------------------------------------------------------------------------------------------------------
// ---------------------------------------------------------------------------------------------------------------------
bool MemoryFile::DoOpenRead(const wchar_t*)
{
	PSD_ASSERT(false, "MemoryFile::DoOpenRead() should not be called directly.");
	return false;
}


// ---------------------------------------------------------------------------------------------------------------------
// ---------------------------------------------------------------------------------------------------------------------
bool MemoryFile::DoOpenWrite(const wchar_t*)
{
	PSD_ASSERT(false, "MemoryFile does not support writing.");
	return false;
}


// ---------------------------------------------------------------------------------------------------------------------
// ---------------------------------------------------------------------------------------------------------------------
bool MemoryFile::DoClose(void)
{
	m_data = nullptr;
	m_size = 0u;
	m_isOpen = false;
	return true;
}


// ---------------------------------------------------------------------------------------------------------------------
// ---------------------------------------------------------------------------------------------------------------------
File::ReadOperation MemoryFile::DoRead(void* buffer, uint32_t count, uint64_t position)
{
	PSD_ASSERT_NOT_NULL(buffer);
	PSD_ASSERT(m_isOpen, "MemoryFile must be opened with Open() before reading.");
	PSD_ASSERT(position + count <= m_size, "Attempting to read past the end of the buffer.");

	memcpy(buffer, m_data + position, count);
	return nullptr;
}


// ---------------------------------------------------------------------------------------------------------------------
// ---------------------------------------------------------------------------------------------------------------------
bool MemoryFile::DoWaitForRead(File::ReadOperation& operation)
{
	PSD_UNUSED(operation);
	return true;
}


// ---------------------------------------------------------------------------------------------------------------------
// ---------------------------------------------------------------------------------------------------------------------
File::WriteOperation MemoryFile::DoWrite(const void*, uint32_t, uint64_t)
{
	PSD_ASSERT(false, "MemoryFile does not support writing.");
	return nullptr;
}


// ---------------------------------------------------------------------------------------------------------------------
// ---------------------------------------------------------------------------------------------------------------------
bool MemoryFile::DoWaitForWrite(File::WriteOperation& operation)
{
	PSD_UNUSED(operation);
	return false;
}


// ---------------------------------------------------------------------------------------------------------------------
// ---------------------------------------------------------------------------------------------------------------------
uint64_t MemoryFile::DoGetSize(void) const
{
	return m_isOpen ? m_size : 0ull;
}

PSD_NAMESPACE_END
