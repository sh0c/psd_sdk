// Copyright 2011-2020, Molecular Matters GmbH <office@molecular-matters.com>
// See LICENSE.txt for licensing details (2-clause BSD License: https://opensource.org/licenses/BSD-2-Clause)

#include "PsdPch.h"
#include "PsdParseDocument.h"

#include "PsdDocument.h"
#include "PsdSyncFileReader.h"
#include "PsdSyncFileUtil.h"
#include "PsdKey.h"
#include "PsdMemoryUtil.h"
#include "PsdAllocator.h"
#include "PsdFile.h"
#include "PsdLog.h"
#include <cstring>


PSD_NAMESPACE_BEGIN

namespace
{
// ---------------------------------------------------------------------------------------------------------------------
// ---------------------------------------------------------------------------------------------------------------------
static uint64_t NormalizeSectionLength(uint64_t value, uint64_t available)
{
	if (value <= available)
		return value;

	const uint64_t upper = value >> 32u;
	const uint64_t lower = value & 0xFFFFFFFFull;
	if ((lower == 0ull) && (upper != 0ull) && (upper <= available))
		return upper;

	return available;
}
}

// ---------------------------------------------------------------------------------------------------------------------
// ---------------------------------------------------------------------------------------------------------------------
Document* CreateDocument(File* file, Allocator* allocator)
{
	SyncFileReader reader(file);
	reader.SetPosition(0u);
	const uint64_t fileSize = file->GetSize();

	// check signature, must be "8BPS"
	{
		const uint32_t signature = fileUtil::ReadFromFileBE<uint32_t>(reader);
		if (signature != util::Key<'8', 'B', 'P', 'S'>::VALUE)
		{
			PSD_ERROR("PsdExtract", "File seems to be corrupt, signature does not match \"8BPS\".");
			return nullptr;
		}
	}

	// check version, PSD uses 1 while PSB (large format) uses 2
	const uint16_t version = fileUtil::ReadFromFileBE<uint16_t>(reader);
	if ((version != 1u) && (version != 2u))
	{
		PSD_ERROR("PsdExtract", "File seems to be corrupt, version does not match 1 or 2.");
		return nullptr;
	}

	// check reserved bytes, must be zero
	{
		const uint8_t expected[6] = { 0u, 0u, 0u, 0u, 0u, 0u };
		uint8_t zeroes[6] = {};
		reader.Read(zeroes, 6u);

		if (memcmp(zeroes, expected, sizeof(uint8_t)*6) != 0)
		{
			PSD_ERROR("PsdExtract", "File seems to be corrupt, reserved bytes are not zero.");
			return nullptr;
		}
	}

	Document* document = memoryUtil::Allocate<Document>(allocator);
	document->isLargeDocument = (version == 2u);

	// read in the number of channels.
	// this is the number of channels contained in the document for all layers, including any alpha channels.
	// e.g. for an RGB document with 3 alpha channels, this would be 3 (RGB) + 3 (Alpha) = 6 channels.
	// however, note that individual layers can have extra channels for transparency masks, vector masks, and user masks.
	// this is different from layer to layer.
	document->channelCount = fileUtil::ReadFromFileBE<uint16_t>(reader);

	// read rest of header information
	document->height = fileUtil::ReadFromFileBE<uint32_t>(reader);
	document->width = fileUtil::ReadFromFileBE<uint32_t>(reader);
	document->bitsPerChannel = fileUtil::ReadFromFileBE<uint16_t>(reader);
	document->colorMode = fileUtil::ReadFromFileBE<uint16_t>(reader);

	const auto readSection32 = [&](Section& section) -> bool
	{
		const uint32_t rawLength = fileUtil::ReadFromFileBE<uint32_t>(reader);
		const uint64_t offset = reader.GetPosition();
		const uint64_t available = (offset < fileSize) ? (fileSize - offset) : 0ull;
		const uint64_t length = NormalizeSectionLength(rawLength, available);
		section.offset = offset;
		section.length = length;
		reader.Skip(length);
		return true;
	};

	const auto readSection64 = [&](Section& section) -> bool
	{
		const uint64_t rawLength = fileUtil::ReadFromFileBE<uint64_t>(reader);
		const uint64_t offset = reader.GetPosition();
		const uint64_t available = (offset < fileSize) ? (fileSize - offset) : 0ull;
		const uint64_t length = NormalizeSectionLength(rawLength, available);
		section.offset = offset;
		section.length = length;
		reader.Skip(length);
		return true;
	};

	// grab offsets into different sections
	{
		if (!readSection32(document->colorModeDataSection))
		{
			DestroyDocument(document, allocator);
			return nullptr;
		}
	}
	{
		if (!readSection32(document->imageResourcesSection))
		{
			DestroyDocument(document, allocator);
			return nullptr;
		}
	}
	{
		const bool result = document->isLargeDocument
			? readSection64(document->layerMaskInfoSection)
			: readSection32(document->layerMaskInfoSection);
		if (!result)
		{
			DestroyDocument(document, allocator);
			return nullptr;
		}
	}
	{
		// note that the image data section does NOT store its length in the first 4 bytes
		const uint64_t offset = reader.GetPosition();
		document->imageDataSection.offset = offset;
		document->imageDataSection.length = (offset < fileSize) ? (fileSize - offset) : 0ull;
	}

	return document;
}


// ---------------------------------------------------------------------------------------------------------------------
// ---------------------------------------------------------------------------------------------------------------------
void DestroyDocument(Document*& document, Allocator* allocator)
{
	PSD_ASSERT_NOT_NULL(document);
	PSD_ASSERT_NOT_NULL(allocator);

	memoryUtil::Free(allocator, document);
}

PSD_NAMESPACE_END
