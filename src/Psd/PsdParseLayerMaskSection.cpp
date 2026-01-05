// Copyright 2011-2020, Molecular Matters GmbH <office@molecular-matters.com>
// See LICENSE.txt for licensing details (2-clause BSD License: https://opensource.org/licenses/BSD-2-Clause)

#include "PsdPch.h"
#include "PsdParseLayerMaskSection.h"

#include "PsdDocument.h"
#include "PsdLayer.h"
#include "PsdChannel.h"
#include "PsdChannelType.h"
#include "PsdLayerMask.h"
#include "PsdVectorMask.h"
#include "PsdSmartObject.h"
#include "PsdMemoryFile.h"
#include "PsdCompressionType.h"
#include "PsdLayerType.h"
#include "PsdFile.h"
#include "PsdLayerMaskSection.h"
#include "PsdKey.h"
#include "PsdBitUtil.h"
#include "PsdCompilerMacros.h"
#include "PsdEndianConversion.h"
#include "PsdSyncFileReader.h"
#include "PsdSyncFileUtil.h"
#include "PsdMemoryUtil.h"
#include "PsdDecompressRle.h"
#include "PsdAllocator.h"
#include "Psdminiz.h"
#include "Psdinttypes.h"
#include "PsdLog.h"
#include <cstring>
#include <limits>
#include <new>
#include <cstdio>

#define PSD_DUMP_SMART_OBJECTS 0
#define PSD_DEBUG_LARGE_LAYER 0


PSD_NAMESPACE_BEGIN

namespace
{
	// ---------------------------------------------------------------------------------------------------------------------
	// ---------------------------------------------------------------------------------------------------------------------
	static uint64_t NormalizeLength(uint64_t value, uint64_t available)
	{
		if (value <= available)
			return value;

		const uint64_t upper = value >> 32u;
		const uint64_t lower = value & 0xFFFFFFFFull;
		if ((lower == 0ull) && (upper != 0ull) && (upper <= available))
			return upper;

		return available;
	}


	// ---------------------------------------------------------------------------------------------------------------------
	// ---------------------------------------------------------------------------------------------------------------------
	static void AssignAsciiNameFromUnicode(Layer* layer)
	{
		if (!layer || !layer->utf16Name || layer->name.GetLength() > 0u)
			return;

		char asciiName[util::FixedSizeString::CAPACITY] = {};
		size_t dst = 0u;
		for (size_t src = 0u; layer->utf16Name[src] != 0u && dst < util::FixedSizeString::CAPACITY - 1u; ++src)
		{
			const uint16_t codePoint = layer->utf16Name[src];
			asciiName[dst++] = (codePoint <= 0x7Fu) ? static_cast<char>(codePoint) : '?';
		}
		asciiName[dst] = '\0';

		if (dst > 0u)
		{
			layer->name.Assign(asciiName);
		}
	}


	struct MaskData
	{
		int32_t top;
		int32_t left;
		int32_t bottom;
		int32_t right;
		uint8_t defaultColor;
		bool isVectorMask;
	};

	// ---------------------------------------------------------------------------------------------------------------------
	// ---------------------------------------------------------------------------------------------------------------------
	static MemoryFile* CreateSmartObjectFile(Allocator* allocator, SmartObject* smartObject)
	{
		PSD_ASSERT_NOT_NULL(allocator);
		PSD_ASSERT_NOT_NULL(smartObject);
		PSD_ASSERT_NOT_NULL(smartObject->data);

		void* memory = allocator->Allocate(sizeof(MemoryFile), PSD_ALIGN_OF(MemoryFile));
		MemoryFile* file = new (memory) MemoryFile(allocator);
		file->Open(smartObject->data, smartObject->size);
		return file;
	}


	// ---------------------------------------------------------------------------------------------------------------------
	// ---------------------------------------------------------------------------------------------------------------------
	static uint32_t ReadBigEndianUInt32(const uint8_t* data)
	{
		return (static_cast<uint32_t>(data[0]) << 24u) |
			(static_cast<uint32_t>(data[1]) << 16u) |
			(static_cast<uint32_t>(data[2]) << 8u) |
			(static_cast<uint32_t>(data[3]));
	}


	// ---------------------------------------------------------------------------------------------------------------------
	// ---------------------------------------------------------------------------------------------------------------------
	static uint64_t ReadBigEndianUInt64(const uint8_t* data)
	{
		return (static_cast<uint64_t>(data[0]) << 56u) |
			(static_cast<uint64_t>(data[1]) << 48u) |
			(static_cast<uint64_t>(data[2]) << 40u) |
			(static_cast<uint64_t>(data[3]) << 32u) |
			(static_cast<uint64_t>(data[4]) << 24u) |
			(static_cast<uint64_t>(data[5]) << 16u) |
			(static_cast<uint64_t>(data[6]) << 8u) |
			(static_cast<uint64_t>(data[7]));
	}


	// ---------------------------------------------------------------------------------------------------------------------
	// ---------------------------------------------------------------------------------------------------------------------
	static const uint8_t* FindPattern(const uint8_t* data, uint64_t length, const char* pattern, size_t patternLength)
	{
		if (!data || !pattern || patternLength == 0u || length < patternLength)
			return nullptr;

		const uint64_t searchLength = length - static_cast<uint64_t>(patternLength) + 1u;
		for (uint64_t i=0; i < searchLength; ++i)
		{
			if (memcmp(data + i, pattern, patternLength) == 0)
			{
				return data + i;
			}
		}

		return nullptr;
	}


	// ---------------------------------------------------------------------------------------------------------------------
	// ---------------------------------------------------------------------------------------------------------------------
	static bool ExtractSmartObjectId(const uint8_t* data, uint32_t length, util::FixedSizeString& smartObjectId)
	{
		static const char pattern[] = { 'I', 'd', 'n', 't', 'T', 'E', 'X', 'T' };
		const uint8_t* location = FindPattern(data, length, pattern, sizeof(pattern));
		if (!location)
		{
			return false;
		}

		const uint8_t* cursor = location + sizeof(pattern);
		if (cursor + sizeof(uint32_t) > data + length)
			return false;

		const uint32_t characterCount = ReadBigEndianUInt32(cursor);
		cursor += sizeof(uint32_t);

		const uint32_t byteCount = characterCount * sizeof(uint16_t);
		if (cursor + byteCount > data + length)
			return false;

		char buffer[128] = {};
		const uint32_t maximumCharacters = static_cast<uint32_t>(sizeof(buffer)-1u);
		const uint32_t toCopy = (characterCount < maximumCharacters) ? characterCount : maximumCharacters;
		for (uint32_t i=0; i < toCopy; ++i)
		{
			const uint16_t codeUnit = static_cast<uint16_t>((cursor[i*2u] << 8u) | cursor[i*2u + 1u]);
			buffer[i] = static_cast<char>(codeUnit & 0xFFu);
		}
		buffer[toCopy] = '\0';

		smartObjectId.Assign(buffer);
		return true;
	}


	// ---------------------------------------------------------------------------------------------------------------------
	// ---------------------------------------------------------------------------------------------------------------------
	static Layer* FindLayerBySmartObjectId(LayerMaskSection* section, const char* smartObjectId)
	{
		if (!section || !section->layers || !smartObjectId)
			return nullptr;

		for (unsigned int i=0; i < section->layerCount; ++i)
		{
			Layer* layer = &section->layers[i];
			if (layer->smartObjectId.IsEqual(smartObjectId))
				return layer;
		}

		return nullptr;
	}


	// ---------------------------------------------------------------------------------------------------------------------
	// ---------------------------------------------------------------------------------------------------------------------
	class MemoryReader
	{
	public:
		MemoryReader(const uint8_t* data, uint64_t length)
			: m_begin(data)
			, m_cursor(data)
			, m_end(data + length)
		{
		}

		uint64_t GetConsumed(void) const
		{
			return (m_cursor >= m_begin) ? static_cast<uint64_t>(m_cursor - m_begin) : 0ull;
		}

		uint64_t Remaining(void) const
		{
			return (m_cursor < m_end) ? static_cast<uint64_t>(m_end - m_cursor) : 0ull;
		}

		const uint8_t* GetPointer(void) const
		{
			return m_cursor;
		}

		bool ReadUInt8(uint8_t& value)
		{
			if (Remaining() < sizeof(uint8_t))
				return false;

			value = *m_cursor++;
			return true;
		}

		bool ReadUInt32(uint32_t& value)
		{
			if (Remaining() < sizeof(uint32_t))
				return false;

			value = ReadBigEndianUInt32(m_cursor);
			m_cursor += sizeof(uint32_t);
			return true;
		}

		bool ReadUInt64(uint64_t& value)
		{
			if (Remaining() < sizeof(uint64_t))
				return false;

			value = ReadBigEndianUInt64(m_cursor);
			m_cursor += sizeof(uint64_t);
			return true;
		}

		bool Skip(uint64_t bytes)
		{
			if (Remaining() < bytes)
				return false;

			m_cursor += bytes;
			return true;
		}

		bool Rewind(uint64_t bytes)
		{
			const uint64_t consumed = GetConsumed();
			if (bytes > consumed)
				return false;

			m_cursor -= bytes;
			return true;
		}

	private:
		const uint8_t* m_begin;
		const uint8_t* m_cursor;
		const uint8_t* m_end;
	};


struct DescriptorContext
{
		const uint8_t* payload;
		uint64_t payloadSize;
		uint32_t targetType;

		explicit DescriptorContext(uint32_t type)
			: payload(nullptr)
			, payloadSize(0ull)
			, targetType(type)
		{
		}
};


// ---------------------------------------------------------------------------------------------------------------------
// ---------------------------------------------------------------------------------------------------------------------
static bool Uses64BitLength(uint32_t key, bool isLargeDocument, bool uses64BitSignature)
{
	if (uses64BitSignature)
		return true;
	if (!isLargeDocument)
		return false;

	switch (key)
	{
		case util::Key<'L', 'M', 's', 'k'>::VALUE: // LMsk
		case util::Key<'L', 'r', '1', '6'>::VALUE:
		case util::Key<'L', 'r', '3', '2'>::VALUE:
		case util::Key<'L', 'a', 'y', 'r'>::VALUE:
		case util::Key<'M', 't', '1', '6'>::VALUE:
		case util::Key<'M', 't', '3', '2'>::VALUE:
		case util::Key<'M', 't', 'r', 'n'>::VALUE:
		case util::Key<'A', 'l', 'p', 'h'>::VALUE:
		case util::Key<'F', 'M', 's', 'k'>::VALUE:
		case util::Key<'l', 'n', 'k', '2'>::VALUE:
		case util::Key<'l', 'n', 'k', '3'>::VALUE:
		case util::Key<'l', 'n', 'k', 'E'>::VALUE:
		case util::Key<'F', 'X', 'i', 'd'>::VALUE:
		case util::Key<'F', 'E', 'i', 'd'>::VALUE:
		case util::Key<'F', 'E', 'L', 'S'>::VALUE:
		case util::Key<'P', 'x', 'S', 'D'>::VALUE:
		case util::Key<'p', 't', 'h', 's'>::VALUE:
		case util::Key<'e', 'x', 't', 'd'>::VALUE:
		case util::Key<'e', 'x', 't', 'n'>::VALUE:
		case util::Key<'c', 'i', 'n', 'f'>::VALUE:
		case util::Key<'a', 'r', 't', 'd'>::VALUE:
			return true;
		default:
			return false;
	}
}


// ---------------------------------------------------------------------------------------------------------------------
// ---------------------------------------------------------------------------------------------------------------------
static bool SkipPadding(MemoryReader& reader, uint32_t consumed, uint32_t divisor)
	{
		if (divisor <= 1u)
			return true;

		const uint32_t remainder = consumed % divisor;
		if (remainder != 0u)
		{
			return reader.Skip(divisor - remainder);
		}

		return true;
	}


	// ---------------------------------------------------------------------------------------------------------------------
	// ---------------------------------------------------------------------------------------------------------------------
	static bool SkipPascalString(MemoryReader& reader, uint32_t padding, util::FixedSizeString* result = nullptr)
	{
		uint8_t length = 0u;
		if (!reader.ReadUInt8(length))
			return false;

		if (reader.Remaining() < length)
			return false;

		const uint8_t* stringData = reader.GetPointer();
		if (!reader.Skip(length))
			return false;

		if (result)
		{
			const uint32_t copyCount = (static_cast<uint32_t>(length) < util::FixedSizeString::CAPACITY-1u)
				? static_cast<uint32_t>(length)
				: (util::FixedSizeString::CAPACITY-1u);
			if (copyCount > 0u)
			{
				char buffer[util::FixedSizeString::CAPACITY] = {};
				memcpy(buffer, stringData, copyCount);
				buffer[copyCount] = '\0';
				result->Assign(buffer);
			}
		}

		const uint32_t consumed = 1u + length;
		return SkipPadding(reader, consumed, padding);
	}


	// ---------------------------------------------------------------------------------------------------------------------
	// ---------------------------------------------------------------------------------------------------------------------
	static bool SkipUnicodeString(MemoryReader& reader, uint32_t padding)
	{
		uint32_t characterCount = 0u;
		if (!reader.ReadUInt32(characterCount))
			return false;

		const uint64_t bytesToSkip = static_cast<uint64_t>(characterCount) * sizeof(uint16_t);
		if (bytesToSkip > reader.Remaining())
		{
			PSD_WARNING("LayerMaskSection", "Unicode string length %" PRIu64 " exceeds available bytes, treating as empty.", bytesToSkip);
			reader.Rewind(sizeof(uint32_t));
			return true;
		}

		if (!reader.Skip(bytesToSkip))
			return false;

		const uint32_t consumed = sizeof(uint32_t) + static_cast<uint32_t>(bytesToSkip);
		return SkipPadding(reader, consumed, padding);
	}


	// ---------------------------------------------------------------------------------------------------------------------
	// ---------------------------------------------------------------------------------------------------------------------
	static bool SkipLengthAndKey(MemoryReader& reader)
	{
		uint32_t length = 0u;
		if (!reader.ReadUInt32(length))
			return false;

		if (length == 0u)
			return reader.Skip(4u);

		if ((length > reader.Remaining()) || (length > 1024u))
		{
			PSD_WARNING("LayerMaskSection", "Descriptor key length %u invalid, treating as fixed-length key.", length);
			return reader.Skip(4u);
		}

		return reader.Skip(length);
	}


	// ---------------------------------------------------------------------------------------------------------------------
	// ---------------------------------------------------------------------------------------------------------------------
	static bool SkipLengthBlock(MemoryReader& reader, uint32_t padding)
	{
		uint32_t length = 0u;
		if (!reader.ReadUInt32(length))
			return false;

		if (!reader.Skip(length))
			return false;

		if (padding > 1u)
		{
			const uint32_t remainder = length % padding;
			if (remainder != 0u)
			{
				return reader.Skip(padding - remainder);
			}
		}

		return true;
	}


	// ---------------------------------------------------------------------------------------------------------------------
	// ---------------------------------------------------------------------------------------------------------------------
	static bool SkipClassStructure(MemoryReader& reader)
	{
		return SkipUnicodeString(reader, 1u) && SkipLengthAndKey(reader);
	}


	// ---------------------------------------------------------------------------------------------------------------------
	// ---------------------------------------------------------------------------------------------------------------------
	static bool SkipPropertyStructure(MemoryReader& reader)
	{
		return SkipUnicodeString(reader, 1u) && SkipLengthAndKey(reader) && SkipLengthAndKey(reader);
	}


	// ---------------------------------------------------------------------------------------------------------------------
	// ---------------------------------------------------------------------------------------------------------------------
	static bool SkipEnumeratedStructure(MemoryReader& reader)
	{
		return SkipLengthAndKey(reader) && SkipLengthAndKey(reader);
	}


	// ---------------------------------------------------------------------------------------------------------------------
	// ---------------------------------------------------------------------------------------------------------------------
	static bool SkipEnumeratedReference(MemoryReader& reader)
	{
		return SkipUnicodeString(reader, 1u) && SkipLengthAndKey(reader) && SkipLengthAndKey(reader) && SkipLengthAndKey(reader);
	}


	// ---------------------------------------------------------------------------------------------------------------------
	// ---------------------------------------------------------------------------------------------------------------------
	static bool SkipOffsetStructure(MemoryReader& reader)
	{
		return SkipUnicodeString(reader, 1u) && SkipLengthAndKey(reader) && reader.Skip(sizeof(uint32_t));
	}


	// ---------------------------------------------------------------------------------------------------------------------
	// ---------------------------------------------------------------------------------------------------------------------
	static bool SkipNameStructure(MemoryReader& reader)
	{
		return SkipUnicodeString(reader, 1u) && SkipLengthAndKey(reader) && SkipUnicodeString(reader, 1u);
	}


	// ---------------------------------------------------------------------------------------------------------------------
	// ---------------------------------------------------------------------------------------------------------------------
	static bool SkipDescriptorValue(MemoryReader& reader, uint32_t type, DescriptorContext* context);


	// ---------------------------------------------------------------------------------------------------------------------
	// ---------------------------------------------------------------------------------------------------------------------
	static bool SkipDescriptorBody(MemoryReader& reader, DescriptorContext* context)
	{
		if (!SkipUnicodeString(reader, 1u))
		{
			PSD_WARNING("LayerMaskSection", "Failed to skip descriptor name.");
			return false;
		}

		if (!SkipLengthAndKey(reader))
		{
			PSD_WARNING("LayerMaskSection", "Failed to skip descriptor class.");
			return false;
		}

		uint32_t itemCount = 0u;
		if (!reader.ReadUInt32(itemCount))
			return false;

		for (uint32_t i=0u; i < itemCount; ++i)
		{
			if (!SkipLengthAndKey(reader))
			{
				PSD_WARNING("LayerMaskSection", "Failed to skip descriptor key.");
				return false;
			}

			uint32_t valueType = 0u;
			if (!reader.ReadUInt32(valueType))
			{
				PSD_WARNING("LayerMaskSection", "Failed to read descriptor value type.");
				return false;
			}

			if (!SkipDescriptorValue(reader, valueType, context))
			{
				PSD_WARNING("LayerMaskSection", "Failed to skip descriptor value of type 0x%08X.", valueType);
				return false;
			}
		}

		return true;
	}


	// ---------------------------------------------------------------------------------------------------------------------
	// ---------------------------------------------------------------------------------------------------------------------
	static bool SkipDescriptorBlock(MemoryReader& reader, DescriptorContext* context)
	{
		uint32_t version = 0u;
		if (!reader.ReadUInt32(version))
			return false;

		if (version == 16u)
		{
			if (!SkipDescriptorBody(reader, context))
			{
				PSD_WARNING("LayerMaskSection", "Failed to skip descriptor block.");
				return false;
			}
			return true;
		}

		// DescriptorBlock2 stores an additional data version.
		uint32_t dataVersion = 0u;
		if (!reader.ReadUInt32(dataVersion))
			return false;

		if (!SkipDescriptorBody(reader, context))
		{
			PSD_WARNING("LayerMaskSection", "Failed to skip descriptor block2 (version=%u dataVersion=%u).", version, dataVersion);
			return false;
		}

		return true;
	}


	// ---------------------------------------------------------------------------------------------------------------------
	// ---------------------------------------------------------------------------------------------------------------------
	static bool SkipObjectArray(MemoryReader& reader, DescriptorContext* context)
	{
		if (!reader.Skip(sizeof(uint32_t)))
			return false;

		if (!SkipUnicodeString(reader, 1u))
			return false;

		if (!SkipLengthAndKey(reader))
			return false;

		uint32_t itemCount = 0u;
		if (!reader.ReadUInt32(itemCount))
			return false;

		for (uint32_t i=0u; i < itemCount; ++i)
		{
			if (!SkipLengthAndKey(reader))
				return false;

			uint32_t valueType = 0u;
			if (!reader.ReadUInt32(valueType))
				return false;

			if (!SkipDescriptorValue(reader, valueType, context))
				return false;
		}

		return true;
	}


	// ---------------------------------------------------------------------------------------------------------------------
	// ---------------------------------------------------------------------------------------------------------------------
	static bool SkipList(MemoryReader& reader, DescriptorContext* context)
	{
		uint32_t count = 0u;
		if (!reader.ReadUInt32(count))
			return false;

		for (uint32_t i=0u; i < count; ++i)
		{
			uint32_t valueType = 0u;
			if (!reader.ReadUInt32(valueType))
				return false;

			if (!SkipDescriptorValue(reader, valueType, context))
				return false;
		}

		return true;
	}


	// ---------------------------------------------------------------------------------------------------------------------
	// ---------------------------------------------------------------------------------------------------------------------
static bool SkipDescriptorValue(MemoryReader& reader, uint32_t type, DescriptorContext* context)
	{
		switch (type)
		{
			case util::Key<'O', 'b', 'j', 'c'>::VALUE:
				return SkipDescriptorBody(reader, context);

			case util::Key<'o', 'b', 'j', ' '>::VALUE:
			case util::Key<'V', 'l', 'L', 's'>::VALUE:
				return SkipList(reader, context);

			case util::Key<'d', 'o', 'u', 'b'>::VALUE:
				return reader.Skip(sizeof(float64_t));

			case util::Key<'U', 'n', 't', 'F'>::VALUE:
				return reader.Skip(4u + sizeof(float64_t));

			case util::Key<'U', 'n', 'F', 'l'>::VALUE:
			{
				uint32_t unit = 0u;
				uint32_t count = 0u;
				if (!reader.ReadUInt32(unit) || !reader.ReadUInt32(count))
					return false;

				const uint64_t bytes = static_cast<uint64_t>(count) * sizeof(float64_t);
				return reader.Skip(bytes);
			}

			case util::Key<'T', 'E', 'X', 'T'>::VALUE:
				return SkipUnicodeString(reader, 1u);

			case util::Key<'e', 'n', 'u', 'm'>::VALUE:
				return SkipEnumeratedStructure(reader);

			case util::Key<'l', 'o', 'n', 'g'>::VALUE:
			case util::Key<'I', 'd', 'n', 't'>::VALUE:
			case util::Key<'i', 'n', 'd', 'x'>::VALUE:
				return reader.Skip(sizeof(int32_t));

			case util::Key<'c', 'o', 'm', 'p'>::VALUE:
				return reader.Skip(sizeof(int64_t));

			case util::Key<'b', 'o', 'o', 'l'>::VALUE:
				return reader.Skip(sizeof(uint8_t));

			case util::Key<'G', 'l', 'b', 'O'>::VALUE:
				return SkipDescriptorBody(reader, context);

			case util::Key<'t', 'y', 'p', 'e'>::VALUE:
			case util::Key<'G', 'l', 'b', 'C'>::VALUE:
			case util::Key<'C', 'l', 's', 's'>::VALUE:
				return SkipClassStructure(reader);

			case util::Key<'O', 'b', 'A', 'r'>::VALUE:
				return SkipObjectArray(reader, context);

			case util::Key<'a', 'l', 'i', 's'>::VALUE:
			case util::Key<'t', 'd', 't', 'a'>::VALUE:
			case util::Key<'P', 't', 'h', ' '>::VALUE:
			{
				uint32_t length = 0u;
				if (!reader.ReadUInt32(length))
					return false;

				if (type == util::Key<'t', 'd', 't', 'a'>::VALUE && context && !context->payload)
				{
					context->payload = reader.GetPointer();
					context->payloadSize = length;
				}

				return reader.Skip(length);
			}

			case util::Key<'p', 'r', 'o', 'p'>::VALUE:
				return SkipPropertyStructure(reader);

			case util::Key<'E', 'n', 'm', 'r'>::VALUE:
				return SkipEnumeratedReference(reader);

			case util::Key<'r', 'e', 'l', 'e'>::VALUE:
				return SkipOffsetStructure(reader);

			case util::Key<'n', 'a', 'm', 'e'>::VALUE:
				return SkipNameStructure(reader);

			default:
			{
				const char typeChars[5] =
				{
					static_cast<char>((type >> 24u) & 0xFFu),
					static_cast<char>((type >> 16u) & 0xFFu),
					static_cast<char>((type >> 8u) & 0xFFu),
					static_cast<char>(type & 0xFFu),
					'\0'
				};
				PSD_WARNING("LayerMaskSection", "Encountered unsupported descriptor value type \"%s\" (0x%08X).", typeChars, type);
				return false;
			}
		}
	}


	// ---------------------------------------------------------------------------------------------------------------------
	// ---------------------------------------------------------------------------------------------------------------------
	static void AssignSmartObjectData(Layer* layer, Allocator* allocator, const uint8_t* psdData, uint64_t size, uint32_t fileType)
	{
		if (!layer || !allocator || !psdData || size == 0u)
			return;

		if (!layer->smartObject)
		{
			layer->smartObject = memoryUtil::Allocate<SmartObject>(allocator);
			layer->smartObject->data = nullptr;
			layer->smartObject->file = nullptr;
			layer->smartObject->fileType = 0u;
			layer->smartObject->fileOffset = 0ull;
			layer->smartObject->size = 0u;
		}

		if (layer->smartObject->file)
		{
			layer->smartObject->file->Close();
			layer->smartObject->file->~MemoryFile();
			allocator->Free(layer->smartObject->file);
			layer->smartObject->file = nullptr;
		}

		allocator->Free(layer->smartObject->data);
		PSD_ASSERT(size <= static_cast<uint64_t>(std::numeric_limits<size_t>::max()), "Smart object payload too large.");
		layer->smartObject->data = allocator->Allocate(static_cast<size_t>(size), 4u);
		memcpy(layer->smartObject->data, psdData, static_cast<size_t>(size));
		layer->smartObject->size = size;
		layer->smartObject->fileType = fileType;
		layer->smartObject->fileOffset = 0ull;
#if PSD_DUMP_SMART_OBJECTS
		static uint32_t dumpIndex = 0u;
		char dumpPath[256] = {};
		std::snprintf(dumpPath, sizeof(dumpPath), "/tmp/smart_dump_%03u.bin", dumpIndex++);
		FILE* dumpFile = std::fopen(dumpPath, "wb");
		if (dumpFile)
		{
			std::fwrite(psdData, 1u, static_cast<size_t>(size), dumpFile);
			std::fclose(dumpFile);
		}
#endif
		layer->smartObject->file = CreateSmartObjectFile(allocator, layer->smartObject);
		PSD_WARNING("LayerMaskSection", "Smart object data stored (%" PRIu64 " bytes).", size);
	}


	struct PendingSmartObjectEntry
	{
		PendingSmartObjectEntry()
			: data(nullptr)
			, size(0ull)
			, fileType(0u)
			, next(nullptr)
		{
			smartObjectId.Clear();
		}

		util::FixedSizeString smartObjectId;
		uint8_t* data;
		uint64_t size;
		uint32_t fileType;
		PendingSmartObjectEntry* next;
	};


	class PendingSmartObjectList
	{
	public:
		explicit PendingSmartObjectList(Allocator* allocator)
			: m_head(nullptr)
			, m_allocator(allocator)
		{
		}

		~PendingSmartObjectList(void)
		{
			Clear();
		}

		void Add(const char* smartObjectId, const uint8_t* data, uint64_t size, uint32_t fileType)
		{
			if (!m_allocator || !smartObjectId || !data || size == 0u)
				return;

			PendingSmartObjectEntry* entry = memoryUtil::Allocate<PendingSmartObjectEntry>(m_allocator);
			entry->smartObjectId.Assign(smartObjectId);
			PSD_WARNING("LayerMaskSection", "Queueing smart object payload for GUID %s (%" PRIu64 " bytes).", smartObjectId, size);
			PSD_ASSERT(size <= static_cast<uint64_t>(std::numeric_limits<size_t>::max()), "Smart object payload too large.");
			entry->data = static_cast<uint8_t*>(m_allocator->Allocate(static_cast<size_t>(size), 4u));
			memcpy(entry->data, data, static_cast<size_t>(size));
			entry->size = size;
			entry->fileType = fileType;
			entry->next = m_head;
			m_head = entry;
		}

		bool AssignToLayer(Layer* layer)
		{
			if (!layer || !m_allocator || layer->smartObjectId.GetLength() == 0u)
				return false;

			PendingSmartObjectEntry** current = &m_head;
			while (*current)
			{
				PendingSmartObjectEntry* entry = *current;
				if (entry->smartObjectId.IsEqual(layer->smartObjectId.c_str()))
				{
					AssignSmartObjectData(layer, m_allocator, entry->data, entry->size, entry->fileType);
					PSD_WARNING("LayerMaskSection", "Assigned smart object data for layer \"%s\" (GUID=%s).", layer->name.c_str(), layer->smartObjectId.c_str());
					m_allocator->Free(entry->data);
					*current = entry->next;
					memoryUtil::Free(m_allocator, entry);
					return true;
				}
				current = &((*current)->next);
			}

			return false;
		}

		void AssignAll(LayerMaskSection* section)
		{
			if (!section || !section->layers)
				return;

			for (unsigned int i=0; i < section->layerCount; ++i)
			{
				AssignToLayer(&section->layers[i]);
			}
		}

		void Clear(void)
		{
			while (m_head)
			{
				PendingSmartObjectEntry* next = m_head->next;
				if (m_head->data)
				{
					m_allocator->Free(m_head->data);
				}
				memoryUtil::Free(m_allocator, m_head);
				m_head = next;
			}
		}

	private:
		PendingSmartObjectEntry* m_head;
		Allocator* m_allocator;
	};


	// ---------------------------------------------------------------------------------------------------------------------
	// ---------------------------------------------------------------------------------------------------------------------
static void ParseLinkedLayerEntries(LayerMaskSection* section, PendingSmartObjectList& pendingObjects, const uint8_t* data, uint64_t length, Allocator* allocator)
{
	if (!section || !section->layers || !data || length == 0u || !allocator)
		return;

	MemoryReader reader(data, length);

	while (reader.Remaining() >= sizeof(uint64_t))
	{
		uint64_t entryLength = 0u;
		if (!reader.ReadUInt64(entryLength))
		{
			break;
		}

		if ((entryLength == 0u) || (reader.Remaining() < entryLength))
		{
			break;
		}

		const uint8_t* entryData = reader.GetPointer();
		reader.Skip(entryLength);

		const uint64_t consumed = reader.GetConsumed();
		const uint64_t padding = (4u - (consumed & 3u)) & 3u;
		if ((padding > 0u) && !reader.Skip(padding))
		{
			break;
		}

		MemoryReader entry(entryData, entryLength);

		uint32_t kind = 0u;
		if (!entry.ReadUInt32(kind))
			continue;

		uint32_t version = 0u;
		if (!entry.ReadUInt32(version))
			continue;

		if ((version < 1u) || (version > 8u))
		{
			PSD_WARNING("LayerMaskSection", "Unsupported linked layer version %u.", version);
			continue;
		}

		util::FixedSizeString guid;
		if (!SkipPascalString(entry, 1u, &guid))
			continue;

		if (!SkipUnicodeString(entry, 1u))
			continue;

		uint32_t fileType = 0u;
		if (!entry.ReadUInt32(fileType))
			continue;

		DescriptorContext descriptorContext(fileType);
		uint32_t creator = 0u;
		if (!entry.ReadUInt32(creator))
			continue;
		PSD_UNUSED(creator);

		uint64_t rawDataSize = 0ull;
		if (!entry.ReadUInt64(rawDataSize))
			continue;

		uint8_t hasOpenDescriptor = 0u;
		if (!entry.ReadUInt8(hasOpenDescriptor))
			continue;

		if (hasOpenDescriptor != 0u)
		{
			if (!SkipDescriptorBlock(entry, &descriptorContext))
			{
				PSD_WARNING("LayerMaskSection", "Failed to skip open descriptor for linked layer \"%s\".", guid.c_str());
				continue;
			}
		}

		if (kind == util::Key<'l', 'i', 'F', 'E'>::VALUE)
		{
			if (!SkipDescriptorBlock(entry, nullptr))
				continue;

			if (version > 3u)
			{
				if (!entry.Skip(sizeof(uint32_t) + 4u + sizeof(float64_t)))
					continue;
			}

			if (!entry.Skip(sizeof(uint64_t)))
				continue;

			if (version > 2u)
			{
				const uint64_t embeddedBytes = NormalizeLength(rawDataSize, entry.Remaining());
				if (!entry.Skip(embeddedBytes))
					continue;
			}
		}
		else if (kind == util::Key<'l', 'i', 'F', 'A'>::VALUE)
		{
			if (!entry.Skip(8u))
				continue;
		}

		const uint8_t* payloadStart = nullptr;
		uint64_t payloadLength = 0ull;
		if (kind == util::Key<'l', 'i', 'F', 'D'>::VALUE)
		{
			const uint64_t availablePayload = entry.Remaining();
			payloadLength = NormalizeLength(rawDataSize, availablePayload);
			if ((payloadLength == 0u) || (entry.Remaining() < payloadLength))
				continue;

			payloadStart = entry.GetPointer();
			if (!entry.Skip(payloadLength))
				continue;

			if (payloadLength < rawDataSize)
			{
				PSD_WARNING("LayerMaskSection", "Smart object payload truncated from %" PRIu64 " bytes to %" PRIu64 " bytes.", rawDataSize, payloadLength);
			}
		}

		const bool hasEmbeddedDescriptorData = (descriptorContext.payload && descriptorContext.payloadSize > 0u);

		if (version >= 5u)
		{
			if (!SkipUnicodeString(entry, 1u))
				continue;
		}
		if (version >= 6u)
		{
			if (!entry.Skip(sizeof(float64_t)))
				continue;
		}
		if (version >= 7u)
		{
			if (!entry.Skip(sizeof(uint8_t)))
				continue;
		}

		if ((kind == util::Key<'l', 'i', 'F', 'E'>::VALUE) && (version == 2u))
		{
			const uint64_t trailingBytes = NormalizeLength(rawDataSize, entry.Remaining());
			if (!entry.Skip(trailingBytes))
				continue;
		}

		const uint8_t* dataToUse = hasEmbeddedDescriptorData ? descriptorContext.payload : payloadStart;
		const uint64_t sizeToUse = hasEmbeddedDescriptorData ? descriptorContext.payloadSize : payloadLength;

		if (!dataToUse || (sizeToUse == 0u))
			continue;

		Layer* targetLayer = FindLayerBySmartObjectId(section, guid.c_str());
		if (targetLayer)
		{
			AssignSmartObjectData(targetLayer, allocator, dataToUse, sizeToUse, fileType);
		}
		else
		{
			pendingObjects.Add(guid.c_str(), dataToUse, sizeToUse, fileType);
		}
	}
}


	// ---------------------------------------------------------------------------------------------------------------------
	// ---------------------------------------------------------------------------------------------------------------------
	static int64_t ReadMaskRectangle(SyncFileReader& reader, MaskData& maskData)
	{
		maskData.top = fileUtil::ReadFromFileBE<int32_t>(reader);
		maskData.left = fileUtil::ReadFromFileBE<int32_t>(reader);
		maskData.bottom = fileUtil::ReadFromFileBE<int32_t>(reader);
		maskData.right = fileUtil::ReadFromFileBE<int32_t>(reader);

		return 4u*sizeof(int32_t);
	}


	// ---------------------------------------------------------------------------------------------------------------------
	// ---------------------------------------------------------------------------------------------------------------------
	static int64_t ReadMaskDensity(SyncFileReader& reader, uint8_t& density)
	{
		density = fileUtil::ReadFromFileBE<uint8_t>(reader);
		return sizeof(uint8_t);
	}


	// ---------------------------------------------------------------------------------------------------------------------
	// ---------------------------------------------------------------------------------------------------------------------
	static int64_t ReadMaskFeather(SyncFileReader& reader, float64_t& feather)
	{
		feather = fileUtil::ReadFromFileBE<float64_t>(reader);
		return sizeof(float64_t);
	}


	// ---------------------------------------------------------------------------------------------------------------------
	// ---------------------------------------------------------------------------------------------------------------------
	static int64_t ReadMaskParameters(SyncFileReader& reader, uint8_t& layerDensity, float64_t& layerFeather, uint8_t& vectorDensity, float64_t& vectorFeather)
	{
		int64_t bytesRead = 0;

		const uint8_t flags = fileUtil::ReadFromFileBE<uint8_t>(reader);
		bytesRead += sizeof(uint8_t);

		const bool hasUserDensity = (flags & (1u << 0)) != 0;
		const bool hasUserFeather = (flags & (1u << 1)) != 0;
		const bool hasVectorDensity = (flags & (1u << 2)) != 0;
		const bool hasVectorFeather = (flags & (1u << 3)) != 0;
		if (hasUserDensity)
		{
			bytesRead += ReadMaskDensity(reader, layerDensity);
		}
		if (hasUserFeather)
		{
			bytesRead += ReadMaskFeather(reader, layerFeather);
		}
		if (hasVectorDensity)
		{
			bytesRead += ReadMaskDensity(reader, vectorDensity);
		}
		if (hasVectorFeather)
		{
			bytesRead += ReadMaskFeather(reader, vectorFeather);
		}

		return bytesRead;
	}


	// ---------------------------------------------------------------------------------------------------------------------
	// ---------------------------------------------------------------------------------------------------------------------
	template <typename T>
	static void ApplyMaskData(const MaskData& maskData, float64_t feather, uint8_t density, T* layerMask)
	{
		layerMask->top = maskData.top;
		layerMask->left = maskData.left;
		layerMask->bottom = maskData.bottom;
		layerMask->right = maskData.right;
		layerMask->feather = feather;
		layerMask->density = density;
		layerMask->defaultColor = maskData.defaultColor;
	}


	// ---------------------------------------------------------------------------------------------------------------------
	// ---------------------------------------------------------------------------------------------------------------------
	template <typename T>
	static unsigned int GetWidth(const T* data)
	{
		if (data->right > data->left)
			return static_cast<unsigned int>(data->right - data->left);

		return 0u;
	}


	// ---------------------------------------------------------------------------------------------------------------------
	// ---------------------------------------------------------------------------------------------------------------------
	template <typename T>
	static unsigned int GetHeight(const T* data)
	{
		if (data->bottom > data->top)
			return static_cast<unsigned int>(data->bottom - data->top);

		return 0u;
	}


	// ---------------------------------------------------------------------------------------------------------------------
	// ---------------------------------------------------------------------------------------------------------------------
	template <typename T>
	static void GetExtents(const T* data, unsigned int& width, unsigned int& height)
	{
		width = GetWidth(data);
		height = GetHeight(data);
	}


	// ---------------------------------------------------------------------------------------------------------------------
	// ---------------------------------------------------------------------------------------------------------------------
	static void GetChannelExtents(const Layer* layer, const Channel* channel, unsigned int& width, unsigned int& height)
	{
		if (channel->type == channelType::TRANSPARENCY_MASK)
		{
			// the channel is the transparency mask, which has the same size as the layer
			return GetExtents(layer, width, height);
		}
		else if (channel->type == channelType::LAYER_OR_VECTOR_MASK)
		{
			// the channel is either the layer or vector mask, depending on how many masks there are in the layer.
			if (layer->vectorMask)
			{
				// a vector mask exists, so this always denotes a vector mask
				return GetExtents(layer->vectorMask, width, height);
			}
			else if (layer->layerMask)
			{
				// no vector mask exists, so the layer mask is the only mask left
				return GetExtents(layer->layerMask, width, height);
			}

			PSD_ASSERT(false, "The code failed to create a mask for this type internally. This should never happen.");
			width = 0;
			height = 0;
			return;
		}
		else if (channel->type == channelType::LAYER_MASK)
		{
			// this type is only valid when there are two masks stored, in which case this always denotes the layer mask
			return GetExtents(layer->layerMask, width, height);
		}

		// this is a color channel which has the same size as the layer
		return GetExtents(layer, width, height);
	}


	// ---------------------------------------------------------------------------------------------------------------------
	// ---------------------------------------------------------------------------------------------------------------------
	static uint8_t GetChannelDefaultColor(const Layer* layer, const Channel* channel)
	{
		if (channel->type == channelType::TRANSPARENCY_MASK)
		{
			return 0u;
		}
		else if (channel->type == channelType::LAYER_OR_VECTOR_MASK)
		{
			if (layer->vectorMask)
			{
				return layer->vectorMask->defaultColor;
			}
			else if (layer->layerMask)
			{
				return layer->layerMask->defaultColor;
			}

			PSD_ASSERT(false, "The code failed to create a mask for this type internally. This should never happen.");
			return 0u;
		}
		else if (channel->type == channelType::LAYER_MASK)
		{
			return layer->layerMask->defaultColor;
		}

		return 0u;
	}


	// ---------------------------------------------------------------------------------------------------------------------
	// ---------------------------------------------------------------------------------------------------------------------
	template <typename T>
	static void MoveChannelToMask(Channel* channel, T* mask)
	{
		mask->data = channel->data;
		mask->fileOffset = channel->fileOffset;

		channel->data = nullptr;
		channel->type = channelType::INVALID;
		channel->fileOffset = 0ull;
	}


	// ---------------------------------------------------------------------------------------------------------------------
	// ---------------------------------------------------------------------------------------------------------------------
	template <typename T>
	void EndianConvert(void* src, unsigned int width, unsigned int height)
	{
		PSD_ASSERT_NOT_NULL(src);

		T* data = static_cast<T*>(src);
		const unsigned int size = width*height;

		for (unsigned int i=0; i < size; ++i)
		{
			data[i] = endianUtil::BigEndianToNative(data[i]);
		}
	}


	// ---------------------------------------------------------------------------------------------------------------------
	// ---------------------------------------------------------------------------------------------------------------------
	template <typename T>
	static void* ReadChannelDataRaw(SyncFileReader& reader, Allocator* allocator, unsigned int width, unsigned int height)
	{
		const unsigned int size = width*height;
		if (size > 0)
		{
			void* planarData = allocator->Allocate(size*sizeof(T), 16u);
			reader.Read(planarData, size*sizeof(T));

			EndianConvert<T>(planarData, width, height);

			return planarData;
		}

		return nullptr;
	}


	// ---------------------------------------------------------------------------------------------------------------------
	// ---------------------------------------------------------------------------------------------------------------------
	template <typename T>
	static void* ReadChannelDataRLE(SyncFileReader& reader, Allocator* allocator, unsigned int width, unsigned int height)
	{
		// the RLE-compressed data is preceded by a 2-byte data count for each scan line
		const unsigned int size = width*height;

		unsigned int rleDataSize = 0u;
		for (unsigned int i=0; i < height; ++i)
		{
			const uint16_t dataCount = fileUtil::ReadFromFileBE<uint16_t>(reader);
			rleDataSize += dataCount;
		}

		if (rleDataSize > 0)
		{
			void* planarData = allocator->Allocate(size*sizeof(T), 16u);

			// decompress RLE
			void* rleData = allocator->Allocate(rleDataSize, 4u);
			{
				reader.Read(rleData, rleDataSize);
				imageUtil::DecompressRle(static_cast<const uint8_t*>(rleData), rleDataSize, static_cast<uint8_t*>(planarData), width*height*sizeof(T));
			}
			allocator->Free(rleData);

			EndianConvert<T>(planarData, width, height);

			return planarData;
		}

		return nullptr;
	}


	// ---------------------------------------------------------------------------------------------------------------------
	// ---------------------------------------------------------------------------------------------------------------------
	template <typename T>
	static void* ReadChannelDataZip(SyncFileReader& reader, Allocator* allocator, unsigned int width, unsigned int height, uint64_t channelSize)
	{
		if (channelSize > 0)
		{
			const unsigned int size = width*height;

			T* planarData = static_cast<T*>(allocator->Allocate(size*sizeof(T), 16));

			PSD_ASSERT(channelSize <= static_cast<uint64_t>(std::numeric_limits<size_t>::max()), "Channel data too large.");
			void* zipData = allocator->Allocate(static_cast<size_t>(channelSize), 4u);
			PSD_ASSERT(channelSize <= static_cast<uint64_t>(std::numeric_limits<uint32_t>::max()), "Channel data chunk too large to read.");
			reader.Read(zipData, static_cast<uint32_t>(channelSize));

			// the zipped data stream has a zlib-header
			const size_t status = tinfl_decompress_mem_to_mem(planarData, size*sizeof(T), zipData, channelSize, TINFL_FLAG_PARSE_ZLIB_HEADER);
			if (status == TINFL_DECOMPRESS_MEM_TO_MEM_FAILED)
			{
				PSD_ERROR("PsdExtract", "Error while unzipping channel data.");
			}

			allocator->Free(zipData);

			EndianConvert<T>(planarData, width, height);

			return planarData;
		}

		return nullptr;
	}


	// ---------------------------------------------------------------------------------------------------------------------
	// ---------------------------------------------------------------------------------------------------------------------
	template <typename T>
	static void ApplyPrediction(Allocator* allocator, void* PSD_RESTRICT planarData, unsigned int width, unsigned int height)
	{
		static_assert(sizeof(T) == -1, "Unknown data type.");
	}


	// ---------------------------------------------------------------------------------------------------------------------
	// ---------------------------------------------------------------------------------------------------------------------
	template <>
	void ApplyPrediction<uint8_t>(Allocator*, void* PSD_RESTRICT planarData, unsigned int width, unsigned int height)
	{
		uint8_t* buffer = static_cast<uint8_t*>(planarData);
		for (unsigned int y = 0; y < height; ++y)
		{
			++buffer;
			for (unsigned int x = 1; x < width; ++x)
			{
				const uint32_t previous = buffer[-1];
				const uint32_t current = buffer[0];
				const uint32_t value = current + previous;

				*buffer++ = static_cast<uint8_t>(value & 0xFFu);
			}
		}
	}


	// ---------------------------------------------------------------------------------------------------------------------
	// ---------------------------------------------------------------------------------------------------------------------
	template <>
	void ApplyPrediction<uint16_t>(Allocator*, void* PSD_RESTRICT planarData, unsigned int width, unsigned int height)
	{
		// 16-bit images are delta-encoded word-by-word.
		// the deltas are big-endian and must be reversed first for further processing. note that this is done
		// in-place with the delta-decoding.
		{
			uint16_t* buffer = static_cast<uint16_t*>(planarData);
			for (unsigned int y=0; y < height; ++y)
			{
				const uint16_t first = *buffer;
				*buffer++ = endianUtil::BigEndianToNative(first);
				for (unsigned int x=1; x < width; ++x)
				{
					buffer[0] = endianUtil::BigEndianToNative(buffer[0]);

					const uint32_t previous = buffer[-1];
					const uint32_t current = buffer[0];
					const uint32_t value = current + previous;

					// note that the data written here is now in little-endian format
					*buffer++ = static_cast<uint16_t>(value & 0xFFFFu);
				}
			}
		}
	}


	// ---------------------------------------------------------------------------------------------------------------------
	// ---------------------------------------------------------------------------------------------------------------------
	template <>
	void ApplyPrediction<float32_t>(Allocator* allocator, void* PSD_RESTRICT planarData, unsigned int width, unsigned int height)
	{
		// delta-decode row by row first
		{
			uint8_t* buffer = static_cast<uint8_t*>(planarData);
			for (unsigned int y=0; y < height; ++y)
			{
				++buffer;
				for (unsigned int x=1; x < width*4; ++x)
				{
					const uint32_t previous = buffer[-1];
					const uint32_t current = buffer[0];
					const uint32_t value = current + previous;

					*buffer++ = static_cast<uint8_t>(value & 0xFFu);
				}
			}
		}

		// the bytes of the 32-bit float are stored in planar fashion per row, big-endian format.
		// interleave the bytes, and store them in little-endian format at the same time.
		uint8_t* rowData = static_cast<uint8_t*>(allocator->Allocate(width*sizeof(float32_t), 16));
		{
			uint8_t* dest = static_cast<uint8_t*>(planarData);
			for (unsigned int y=0; y < height; ++y)
			{
				// copy first row of data to backup storage, because it will be overwritten inside our loop.
				// note that this operation cannot be done in-place, that's why we work row by row.
				memcpy(rowData, dest, width*sizeof(float32_t));

				const uint8_t* src0 = rowData;
				const uint8_t* src1 = rowData + 1*width;
				const uint8_t* src2 = rowData + 2*width;
				const uint8_t* src3 = rowData + 3*width;

				for (unsigned int x=0; x < width; ++x)
				{
					// write data in little-endian format
					dest[0] = *src3++;
					dest[1] = *src2++;
					dest[2] = *src1++;
					dest[3] = *src0++;
					dest += 4u;
				}
			}
		}

		allocator->Free(rowData);
	}


	// ---------------------------------------------------------------------------------------------------------------------
	// ---------------------------------------------------------------------------------------------------------------------
	template <typename T>
	static void* ReadChannelDataZipPrediction(SyncFileReader& reader, Allocator* allocator, unsigned int width, unsigned int height, uint64_t channelSize)
	{
		if (channelSize > 0)
		{
			const unsigned int size = width*height;

			T* planarData = static_cast<T*>(allocator->Allocate(size*sizeof(T), 16));

			PSD_ASSERT(channelSize <= static_cast<uint64_t>(std::numeric_limits<size_t>::max()), "Channel data too large.");
			void* zipData = allocator->Allocate(static_cast<size_t>(channelSize), 4u);
			PSD_ASSERT(channelSize <= static_cast<uint64_t>(std::numeric_limits<uint32_t>::max()), "Channel data chunk too large to read.");
			reader.Read(zipData, static_cast<uint32_t>(channelSize));

			// the zipped data stream has a zlib-header
			const size_t status = tinfl_decompress_mem_to_mem(planarData, size*sizeof(T), zipData, channelSize, TINFL_FLAG_PARSE_ZLIB_HEADER);
			if (status == TINFL_DECOMPRESS_MEM_TO_MEM_FAILED)
			{
				PSD_ERROR("PsdExtract", "Error while unzipping channel data.");
			}

			allocator->Free(zipData);

			// the data generated by applying the prediction data is already in little-endian format, so it doesn't have to be
			// endian converted further.
			ApplyPrediction<T>(allocator, planarData, width, height);

			return planarData;
		}

		return nullptr;
	}


	// ---------------------------------------------------------------------------------------------------------------------
	// ---------------------------------------------------------------------------------------------------------------------
static LayerMaskSection* ParseLayer(const Document* document, SyncFileReader& reader, Allocator* allocator, uint64_t sectionOffset, uint64_t sectionLength, uint64_t layerLength, uint64_t fileSize, PendingSmartObjectList* pendingSmartObjects)
{
	PSD_ASSERT_NOT_NULL(pendingSmartObjects);

	LayerMaskSection* layerMaskSection = memoryUtil::Allocate<LayerMaskSection>(allocator);
	layerMaskSection->layers = nullptr;
	layerMaskSection->layerCount = 0u;
	layerMaskSection->overlayColorSpace = 0u;
	layerMaskSection->opacity = 0u;
	layerMaskSection->kind = 128u;
	layerMaskSection->hasTransparencyMask = false;

	if (layerLength != 0)
	{
		const uint64_t layerDataStart = reader.GetPosition();
		SyncFileReader metadataReader = reader;
		metadataReader.SetPosition(layerDataStart);

		{
			SyncFileReader& reader = metadataReader;

			// read the layer count. if it is a negative number, its absolute value is the number of layers and the 
			// first alpha channel contains the transparency data for the merged result.
			// this will also be reflected in the channelCount of the document.
			int16_t layerCount = fileUtil::ReadFromFileBE<int16_t>(reader);
			layerMaskSection->hasTransparencyMask = (layerCount < 0);
			if (layerCount < 0)
				layerCount = -layerCount;

			layerMaskSection->layerCount = static_cast<unsigned int>(layerCount);
			layerMaskSection->layers = memoryUtil::AllocateArray<Layer>(allocator, layerMaskSection->layerCount);

			// read layer record for each layer
			for (unsigned int i=0; i < layerMaskSection->layerCount; ++i)
			{
				const unsigned int layerIndex = i;
				Layer* layer = &layerMaskSection->layers[i];
				layer->parent = nullptr;
				layer->utf16Name = nullptr;
				layer->smartObjectId.Clear();
				layer->layerMask = nullptr;
				layer->vectorMask = nullptr;
				layer->smartObject = nullptr;
				layer->type = layerType::ANY;
				layer->isPassThrough = false;

				layer->top = fileUtil::ReadFromFileBE<int32_t>(reader);
				layer->left = fileUtil::ReadFromFileBE<int32_t>(reader);
				layer->bottom = fileUtil::ReadFromFileBE<int32_t>(reader);
				layer->right = fileUtil::ReadFromFileBE<int32_t>(reader);

				// number of channels in the layer.
				// this includes channels for transparency, layer, and vector masks, if any.
				const uint16_t channelCount = fileUtil::ReadFromFileBE<uint16_t>(reader);
				layer->channelCount = channelCount;
				layer->channels = memoryUtil::AllocateArray<Channel>(allocator, channelCount);

				// parse each channel
				for (unsigned int j=0; j < channelCount; ++j)
				{
					Channel* channel = &layer->channels[j];
					channel->fileOffset = 0ull;
					channel->data = nullptr;
					channel->type = fileUtil::ReadFromFileBE<int16_t>(reader);
						if (document->isLargeDocument)
						{
							const uint64_t size64 = fileUtil::ReadFromFileBE<uint64_t>(reader);
							const uint64_t remainingFile = (reader.GetPosition() < fileSize) ? (fileSize - reader.GetPosition()) : 0ull;
							channel->size = NormalizeLength(size64, remainingFile);
						}
						else
						{
							const uint64_t size32 = fileUtil::ReadFromFileBE<uint32_t>(reader);
							const uint64_t remainingFile = (reader.GetPosition() < fileSize) ? (fileSize - reader.GetPosition()) : 0ull;
							channel->size = NormalizeLength(size32, remainingFile);
						}
				}
#if PSD_DEBUG_LARGE_LAYER
				if (document->isLargeDocument && layerIndex < 4u)
				{
					PSD_WARNING("LayerMaskSection", "Layer %u rect [%d,%d,%d,%d] channels=%u", layerIndex, layer->top, layer->left, layer->bottom, layer->right, channelCount);
					for (unsigned int j=0; j < channelCount; ++j)
					{
						const Channel* channel = &layer->channels[j];
						PSD_WARNING("LayerMaskSection", "  Channel %u type=%d size=%" PRIu64, j, channel->type, channel->size);
					}
					PSD_WARNING("LayerMaskSection", "  Reader position before signature: %" PRIu64, reader.GetPosition());
				}
#endif

				// blend mode signature must be '8BIM'
				const uint32_t blendModeSignature = fileUtil::ReadFromFileBE<uint32_t>(reader);
				if (blendModeSignature != util::Key<'8', 'B', 'I', 'M'>::VALUE)
				{
					PSD_ERROR("LayerMaskSection", "Layer mask info section seems to be corrupt, signature 0x%08X does not match \"8BIM\".", blendModeSignature);
					return layerMaskSection;
				}

				layer->blendModeKey = fileUtil::ReadFromFileBE<uint32_t>(reader);
				layer->opacity = fileUtil::ReadFromFileBE<uint8_t>(reader);
				layer->clipping = fileUtil::ReadFromFileBE<uint8_t>(reader);

				// extract flag information into layer struct
				{
					const uint8_t flags = fileUtil::ReadFromFileBE<uint8_t>(reader);
					layer->isVisible = !((flags & (1u << 1)) != 0);
				}

				// skip filler byte
				{
					const uint8_t filler = fileUtil::ReadFromFileBE<uint8_t>(reader);
					PSD_UNUSED(filler);
				}

				const uint64_t rawExtraDataLength = static_cast<uint64_t>(fileUtil::ReadFromFileBE<uint32_t>(reader));
				const uint64_t sectionEnd = sectionOffset + sectionLength;
				const uint64_t remainingInSection = (reader.GetPosition() < sectionEnd) ? (sectionEnd - reader.GetPosition()) : 0ull;
				const uint64_t extraDataLength = NormalizeLength(rawExtraDataLength, remainingInSection);
				uint64_t remainingExtraData = extraDataLength;
				const uint32_t rawLayerMaskDataLength = fileUtil::ReadFromFileBE<uint32_t>(reader);
				if (remainingExtraData >= sizeof(uint32_t))
				{
					remainingExtraData -= sizeof(uint32_t);
				}
				else
				{
					remainingExtraData = 0ull;
				}
				const uint64_t layerMaskDataLength = NormalizeLength(rawLayerMaskDataLength, remainingExtraData);

				// the layer mask data section is weird. it may contain extra data for masks, such as density and feather parameters.
				// there are 3 main possibilities:
				//	*) length == zero		->	skip this section
				//	*) length == [20, 28]	->	there is one mask, and that could be either a layer or vector mask.
				//								the mask flags give rise to mask parameters. they store the mask type, and additional parameters, if any.
				//								there might be some padding at the end of this section, and its size depends on which parameters are there.
				//	*) length == [36, 56]	->	there are two masks. the first mask has parameters, but does NOT store flags yet.
				//								instead, there comes a second section with the same info (flags, default color, rectangle), and
				//								the parameters follow after that. there is also padding at the end of this second section.
				if (layerMaskDataLength != 0)
				{
					// there can be at most two masks, one layer and one vector mask
					MaskData maskData[2] = {};
					unsigned int maskCount = 1u;

					float64_t layerFeather = 0.0;
					float64_t vectorFeather = 0.0;
					uint8_t layerDensity = 0;
					uint8_t vectorDensity = 0;

					int64_t toRead = layerMaskDataLength;

					// enclosing rectangle
					toRead -= ReadMaskRectangle(reader, maskData[0]);

					maskData[0].defaultColor = fileUtil::ReadFromFileBE<uint8_t>(reader);
					toRead -= sizeof(uint8_t);

					const uint8_t maskFlags = fileUtil::ReadFromFileBE<uint8_t>(reader);
					toRead -= sizeof(uint8_t);

					maskData[0].isVectorMask = (maskFlags & (1u << 3)) != 0;
					bool maskHasParameters = (maskFlags & (1u << 4)) != 0;
					if (maskHasParameters && (layerMaskDataLength <= 28))
					{
						toRead -= ReadMaskParameters(reader, layerDensity, layerFeather, vectorDensity, vectorFeather);
					}

					// check if there is enough data left for another section of mask data
					if (toRead >= 18)
					{
						// in case there is still data left to read, the following values are for the real layer mask.
						// the data we just read was for the vector mask.
						maskCount = 2u;

						const uint8_t realFlags = fileUtil::ReadFromFileBE<uint8_t>(reader);
						toRead -= sizeof(uint8_t);

						maskData[1].defaultColor = fileUtil::ReadFromFileBE<uint8_t>(reader);
						toRead -= sizeof(uint8_t);

						toRead -= ReadMaskRectangle(reader, maskData[1]);

						maskData[1].isVectorMask = (realFlags & (1u << 3)) != 0;

						// note the OR here. whether the following section has mask parameter data or not is influenced by
						// the availability of parameter data of the previous mask!
						maskHasParameters |= ((realFlags & (1u << 4)) != 0);
						if (maskHasParameters)
						{
							toRead -= ReadMaskParameters(reader, layerDensity, layerFeather, vectorDensity, vectorFeather);
						}
					}

					// skip the remaining padding bytes, if any
					PSD_ASSERT(toRead >= 0, "Parsing failed, %" PRId64 "bytes left.", toRead);
					reader.Skip(static_cast<uint64_t>(toRead));
					if (remainingExtraData >= layerMaskDataLength)
					{
						remainingExtraData -= layerMaskDataLength;
					}
					else
					{
						remainingExtraData = 0ull;
					}

					// apply mask data to our own data structures
					for (unsigned int mask=0; mask < maskCount; ++mask)
					{
						const bool isVectorMask = maskData[mask].isVectorMask;
						if (isVectorMask)
						{
							PSD_ASSERT(layer->vectorMask == nullptr, "A vector mask already exists.");
							layer->vectorMask = memoryUtil::Allocate<VectorMask>(allocator);
							layer->vectorMask->data = nullptr;
							layer->vectorMask->fileOffset = 0ull;
							ApplyMaskData(maskData[mask], vectorFeather, vectorDensity, layer->vectorMask);
						}
						else
						{
							PSD_ASSERT(layer->layerMask == nullptr, "A layer mask already exists.");
							layer->layerMask = memoryUtil::Allocate<LayerMask>(allocator);
							layer->layerMask->data = nullptr;
							layer->layerMask->fileOffset = 0ull;
							ApplyMaskData(maskData[mask], layerFeather, layerDensity, layer->layerMask);
						}
					}
				}

				// skip blending ranges data, we are not interested in that for now
				const uint32_t rawLayerBlendingRangesDataLength = fileUtil::ReadFromFileBE<uint32_t>(reader);
				if (remainingExtraData >= sizeof(uint32_t))
				{
					remainingExtraData -= sizeof(uint32_t);
				}
				else
				{
					remainingExtraData = 0ull;
				}
				const uint64_t layerBlendingRangesDataLength = NormalizeLength(rawLayerBlendingRangesDataLength, remainingExtraData);
				reader.Skip(layerBlendingRangesDataLength);
				if (remainingExtraData >= layerBlendingRangesDataLength)
				{
					remainingExtraData -= layerBlendingRangesDataLength;
				}
				else
				{
					remainingExtraData = 0ull;
				}

				// the layer name is stored as pascal string, padded to a multiple of 4
				char layerName[512] = {};
				const uint8_t nameLength = fileUtil::ReadFromFileBE<uint8_t>(reader);
				if (remainingExtraData >= sizeof(uint8_t))
				{
					remainingExtraData -= sizeof(uint8_t);
				}
				else
				{
					remainingExtraData = 0ull;
				}
				const uint32_t paddedNameLength = bitUtil::RoundUpToMultiple(nameLength + 1u, 4u);
				const uint64_t desiredNameBytes = (paddedNameLength > 0u) ? (paddedNameLength - 1u) : 0u;
				const uint64_t actualNameBytes = NormalizeLength(desiredNameBytes, remainingExtraData);
				const uint32_t bytesToRead = static_cast<uint32_t>(actualNameBytes);
				if (bytesToRead > 0u)
				{
					const uint32_t toCopy = (bytesToRead < sizeof(layerName)-1u) ? bytesToRead : static_cast<uint32_t>(sizeof(layerName)-1u);
					if (toCopy > 0u)
					{
						reader.Read(layerName, toCopy);
					}
					if (bytesToRead > toCopy)
					{
						reader.Skip(bytesToRead - toCopy);
					}
				}
				if (remainingExtraData >= actualNameBytes)
				{
					remainingExtraData -= actualNameBytes;
				}
				else
				{
					remainingExtraData = 0ull;
				}

				layer->name.Assign(layerName);

				// read Additional Layer Information that exists since Photoshop 4.0.
				// getting the size of this data is a bit awkward, because it's not stored explicitly somewhere. furthermore,
				// the PSD format sometimes includes the 4-byte length in its section size, and sometimes not.
				int64_t toRead = static_cast<int64_t>(remainingExtraData);
				while (toRead > 0)
				{
					const uint32_t signature = fileUtil::ReadFromFileBE<uint32_t>(reader);
					const bool uses64BitSignature = (signature == util::Key<'8', 'B', '6', '4'>::VALUE);
					if ((signature != util::Key<'8', 'B', 'I', 'M'>::VALUE) && !uses64BitSignature)
					{
						PSD_ERROR("LayerMaskSection", "Additional Layer Information section seems to be corrupt, signature 0x%08X does not match \"8BIM\".", signature);
						return layerMaskSection;
					}

					const uint32_t key = fileUtil::ReadFromFileBE<uint32_t>(reader);
					const bool uses64BitLengths = Uses64BitLength(key, document->isLargeDocument, uses64BitSignature);

					const uint64_t headerSize = 2u*sizeof(uint32_t) + (uses64BitLengths ? sizeof(uint64_t) : sizeof(uint32_t));
					const uint64_t availableInfo = (toRead > static_cast<int64_t>(headerSize)) ? static_cast<uint64_t>(toRead - headerSize) : 0ull;

					// length needs to be rounded to an even number
					const uint64_t rawDataLength = uses64BitLengths ? fileUtil::ReadFromFileBE<uint64_t>(reader) : static_cast<uint64_t>(fileUtil::ReadFromFileBE<uint32_t>(reader));
					const uint64_t dataLengthUnpadded = NormalizeLength(rawDataLength, availableInfo);
					uint64_t paddedLength = bitUtil::RoundUpToMultiple<uint64_t>(dataLengthUnpadded, 2u);
					if (paddedLength > availableInfo)
					{
						paddedLength = availableInfo;
					}
					uint64_t dataLength = dataLengthUnpadded;
					if (dataLength > paddedLength)
					{
						dataLength = paddedLength;
					}

					// read "Section divider setting" to identify whether a layer is a group, or a section divider
					if (key == util::Key<'l', 's', 'c', 't'>::VALUE)
					{
						if (dataLength >= 4u)
						{
							layer->type = fileUtil::ReadFromFileBE<uint32_t>(reader);

							// there may be another blend mode here to tell us if the group is pass-through
							if(dataLength >= 12u)
							{
								const uint32_t lsctKey = fileUtil::ReadFromFileBE<uint32_t>(reader);
								const uint32_t modeKey = fileUtil::ReadFromFileBE<uint32_t>(reader);
								if (lsctKey == util::Key<'8', 'B', 'I', 'M'>::VALUE && modeKey == util::Key<'p', 'a', 's', 's'>::VALUE)
								{
									layer->isPassThrough = true;
								}

								if (dataLength > 12u)
								{
									reader.Skip(dataLength - 12u);
								}
							}
							else if (dataLength > 4u)
							{
								// skip the rest of the data
								reader.Skip(dataLength - 4u);
							}
						}
						else
						{
							reader.Skip(dataLength);
						}
					}
					// read Unicode layer name
					else if (key == util::Key<'l', 'u', 'n', 'i'>::VALUE)
					{
						if (dataLength >= sizeof(uint32_t))
						{
							// PSD Unicode strings store 4 bytes for the number of characters, NOT bytes, followed by
							// 2-byte UTF16 Unicode data without the terminating null.
							const uint32_t characterCountWithoutNull = fileUtil::ReadFromFileBE<uint32_t>(reader);
							layer->utf16Name = memoryUtil::AllocateArray<uint16_t>(allocator, characterCountWithoutNull + 1u);

							for (uint32_t c = 0u; c < characterCountWithoutNull; ++c)
							{
								layer->utf16Name[c] = fileUtil::ReadFromFileBE<uint16_t>(reader);
							}
							layer->utf16Name[characterCountWithoutNull] = 0u;

							AssignAsciiNameFromUnicode(layer);

							const uint32_t consumed = 4u + characterCountWithoutNull * sizeof(uint16_t);
							if (dataLength > consumed)
							{
								reader.Skip(dataLength - consumed);
							}
						}
						else
						{
							reader.Skip(dataLength);
						}
					}
					else if (key == util::Key<'S', 'o', 'L', 'd'>::VALUE)
					{
						if (dataLength > 0u)
						{
							PSD_ASSERT(dataLength <= static_cast<uint64_t>(std::numeric_limits<size_t>::max()), "Descriptor too large.");
							uint8_t* descriptor = static_cast<uint8_t*>(allocator->Allocate(static_cast<size_t>(dataLength), 4u));
							PSD_ASSERT(dataLength <= static_cast<uint64_t>(std::numeric_limits<uint32_t>::max()), "Descriptor chunk too large to read.");
							reader.Read(descriptor, static_cast<uint32_t>(dataLength));
							if (ExtractSmartObjectId(descriptor, dataLength, layer->smartObjectId))
							{
								pendingSmartObjects->AssignToLayer(layer);
							}
							allocator->Free(descriptor);
						}
					}
					else if (key == util::Key<'l', 'n', 'k', '2'>::VALUE)
					{
						PSD_WARNING("LayerMaskSection", "Encountered global lnk2 block of %" PRIu64 " bytes.", dataLength);
						if (dataLength > 0u)
					{
						PSD_ASSERT(dataLength <= static_cast<uint64_t>(std::numeric_limits<size_t>::max()), "Linked layer payload too large.");
						uint8_t* linkedLayerData = static_cast<uint8_t*>(allocator->Allocate(static_cast<size_t>(dataLength), 4u));
						PSD_ASSERT(dataLength <= static_cast<uint64_t>(std::numeric_limits<uint32_t>::max()), "Linked layer chunk too large to read.");
						reader.Read(linkedLayerData, static_cast<uint32_t>(dataLength));
						ParseLinkedLayerEntries(layerMaskSection, *pendingSmartObjects, linkedLayerData, dataLength, allocator);
						allocator->Free(linkedLayerData);
					}
				}
					else
					{
						reader.Skip(dataLength);
					}

					if (paddedLength > dataLength)
					{
						reader.Skip(paddedLength - dataLength);
					}

					toRead -= static_cast<int64_t>(headerSize + paddedLength);
				}
			}
		}

		reader.SetPosition(metadataReader.GetPosition());

			// walk through the layers and channels, but don't extract their data just yet. only save the file offset for extracting the
			// data later.
			const uint64_t lengthFieldSize = document->isLargeDocument ? 8u : 4u;
			const bool hasLengthPrefix = (sectionLength != 0u);
			const uint64_t layerDataStartWithPrefix = hasLengthPrefix ? (sectionOffset + lengthFieldSize) : sectionOffset;
			const uint64_t layerDataEnd = layerDataStartWithPrefix + layerLength;
			for (unsigned int i=0; i < layerMaskSection->layerCount; ++i)
			{
				Layer* layer = &layerMaskSection->layers[i];
				const unsigned int channelCount = layer->channelCount;
				for (unsigned int j=0; j < channelCount; ++j)
				{
					Channel* channel = &layer->channels[j];
					channel->fileOffset = reader.GetPosition();

					const uint64_t currentPos = reader.GetPosition();
					const uint64_t remainingLayerData = (currentPos < layerDataEnd) ? (layerDataEnd - currentPos) : 0ull;
					const uint64_t safeSize = (channel->size <= remainingLayerData) ? channel->size : remainingLayerData;
					if (safeSize < channel->size)
					{
						PSD_WARNING("LayerMaskSection", "Channel data exceeds available layer data. Truncating from %" PRIu64 " to %" PRIu64 ".", channel->size, safeSize);
					}
					channel->size = safeSize;
					reader.Skip(safeSize);
				}
			}
		}

		if (sectionLength > 0u)
		{
			// start loading at the global layer mask info section, located after the Layer Information Section.
			// note that the 4 bytes that stored the length of the section are not included in the length itself.
			const uint64_t globalInfoSectionOffset = (sectionLength != 0u)
				? (sectionOffset + layerLength + (document->isLargeDocument ? 8u : 4u))
				: (sectionOffset + layerLength);
			reader.SetPosition(globalInfoSectionOffset);

			// work out how many bytes are left to read at this point. we need that to figure out the size of the last
			// optional section, the Additional Layer Information.
			if (sectionOffset + sectionLength > globalInfoSectionOffset)
			{
				int64_t toRead = static_cast<int64_t>((sectionOffset + sectionLength) - globalInfoSectionOffset);
				const uint32_t globalLayerMaskLength = fileUtil::ReadFromFileBE<uint32_t>(reader);
				toRead -= sizeof(uint32_t);

				if (globalLayerMaskLength != 0)
				{
					layerMaskSection->overlayColorSpace = fileUtil::ReadFromFileBE<uint16_t>(reader);

					// 4*2 byte color components
					reader.Skip(8);

					layerMaskSection->opacity = fileUtil::ReadFromFileBE<uint16_t>(reader);
					layerMaskSection->kind = fileUtil::ReadFromFileBE<uint8_t>(reader);

					toRead -= 2u*sizeof(uint16_t) + sizeof(uint8_t) + 8u;

					// filler bytes (zeroes)
					const uint32_t remaining = globalLayerMaskLength - 2u*sizeof(uint16_t) - sizeof(uint8_t) - 8u;
					reader.Skip(remaining);

					toRead -= remaining;
				}

				// are there still bytes left to read? then this is the Additional Layer Information that exists since Photoshop 4.0.
				while (toRead > 0)
				{
					const uint32_t signature = fileUtil::ReadFromFileBE<uint32_t>(reader);
					const bool uses64BitSignature = (signature == util::Key<'8', 'B', '6', '4'>::VALUE);
					if ((signature != util::Key<'8', 'B', 'I', 'M'>::VALUE) && !uses64BitSignature)
					{
						PSD_ERROR("AdditionalLayerInfo", "Additional Layer Information section seems to be corrupt, signature 0x%08X does not match \"8BIM\".", signature);
						return layerMaskSection;
					}

					const uint32_t key = fileUtil::ReadFromFileBE<uint32_t>(reader);
					const bool uses64BitLengths = Uses64BitLength(key, document->isLargeDocument, uses64BitSignature);

					const uint64_t headerSize = 2u*sizeof(uint32_t) + (uses64BitLengths ? sizeof(uint64_t) : sizeof(uint32_t));
					const uint64_t availableInfo = (toRead > static_cast<int64_t>(headerSize)) ? static_cast<uint64_t>(toRead - headerSize) : 0ull;

					// again, length is rounded to a multiple of 4
					const uint64_t rawLength = uses64BitLengths ? fileUtil::ReadFromFileBE<uint64_t>(reader) : static_cast<uint64_t>(fileUtil::ReadFromFileBE<uint32_t>(reader));
					const uint64_t dataLengthUnpadded = NormalizeLength(rawLength, availableInfo);
					uint64_t paddedLength = bitUtil::RoundUpToMultiple<uint64_t>(dataLengthUnpadded, 4u);
					if (paddedLength > availableInfo)
					{
						paddedLength = availableInfo;
					}
					uint64_t dataLength = dataLengthUnpadded;
					if (dataLength > paddedLength)
					{
						dataLength = paddedLength;
					}

		if (key == util::Key<'L', 'r', '1', '6'>::VALUE)
		{
			const uint64_t offset = reader.GetPosition();
			DestroyLayerMaskSection(layerMaskSection, allocator);
			layerMaskSection = ParseLayer(document, reader, allocator, 0u, 0u, dataLength, fileSize, pendingSmartObjects);
			reader.SetPosition(offset + paddedLength);
		}
		else if (key == util::Key<'L', 'r', '3', '2'>::VALUE)
		{
			const uint64_t offset = reader.GetPosition();
			DestroyLayerMaskSection(layerMaskSection, allocator);
			layerMaskSection = ParseLayer(document, reader, allocator, 0u, 0u, dataLength, fileSize, pendingSmartObjects);
			reader.SetPosition(offset + paddedLength);
					}
					else if (key == util::Key<'v', 'm', 's', 'k'>::VALUE)
					{
						// TODO: could read extra vector mask data here
						reader.Skip(dataLength);
						if (paddedLength > dataLength)
						{
							reader.Skip(paddedLength - dataLength);
						}
					}
					else if (key == util::Key<'l', 'n', 'k', '2'>::VALUE)
					{
						PSD_WARNING("LayerMaskSection", "Encountered per-layer lnk2 block of %" PRIu64 " bytes.", dataLength);
						if (dataLength > 0u)
						{
							PSD_ASSERT(dataLength <= static_cast<uint64_t>(std::numeric_limits<size_t>::max()), "Linked layer payload too large.");
							uint8_t* linkedLayerData = static_cast<uint8_t*>(allocator->Allocate(static_cast<size_t>(dataLength), 4u));
							PSD_ASSERT(dataLength <= static_cast<uint64_t>(std::numeric_limits<uint32_t>::max()), "Linked layer chunk too large to read.");
							reader.Read(linkedLayerData, static_cast<uint32_t>(dataLength));
							ParseLinkedLayerEntries(layerMaskSection, *pendingSmartObjects, linkedLayerData, dataLength, allocator);
							allocator->Free(linkedLayerData);
						}
						if (paddedLength > dataLength)
						{
							reader.Skip(paddedLength - dataLength);
						}
					}
					else
					{
						reader.Skip(paddedLength);
					}

					toRead -= static_cast<int64_t>(headerSize + paddedLength);
				}
			}
		}

		pendingSmartObjects->AssignAll(layerMaskSection);
		return layerMaskSection;
	}
}


// ---------------------------------------------------------------------------------------------------------------------
// ---------------------------------------------------------------------------------------------------------------------
LayerMaskSection* ParseLayerMaskSection(const Document* document, File* file, Allocator* allocator)
{
	PSD_ASSERT_NOT_NULL(file);
	PSD_ASSERT_NOT_NULL(allocator);
	const uint64_t fileSize = file->GetSize();

	// if there are no layers or masks, this section is just 4 bytes: the length field, which is set to zero.
	const Section& section = document->layerMaskInfoSection;
	if (section.length == 0)
	{
		PSD_ERROR("PSD", "Document does not contain a layer mask section.");
		return nullptr;
	}

	SyncFileReader reader(file);
	reader.SetPosition(section.offset);

	const uint64_t lengthFieldSize = document->isLargeDocument ? 8u : 4u;
	const uint64_t rawLayerInfoSectionLength = document->isLargeDocument ? fileUtil::ReadFromFileBE<uint64_t>(reader) : static_cast<uint64_t>(fileUtil::ReadFromFileBE<uint32_t>(reader));
	const uint64_t availableInSection = (document->layerMaskInfoSection.length > lengthFieldSize) ? (document->layerMaskInfoSection.length - lengthFieldSize) : 0ull;
	const uint64_t remainingFile = (reader.GetPosition() < fileSize) ? (fileSize - reader.GetPosition()) : 0ull;
	const uint64_t availableLayerInfo = (availableInSection < remainingFile) ? availableInSection : remainingFile;
	const uint64_t layerInfoSectionLength = NormalizeLength(rawLayerInfoSectionLength, availableLayerInfo);

	PendingSmartObjectList pendingSmartObjects(allocator);
	LayerMaskSection* layerMaskSection = ParseLayer(document, reader, allocator, section.offset, section.length, layerInfoSectionLength, fileSize, &pendingSmartObjects);

	// build the layer hierarchy
	if (layerMaskSection && layerMaskSection->layers)
	{
		Layer* layerStack[256] = {};
		layerStack[0] = nullptr;
		int stackIndex = 0;

		for (unsigned int i=0; i < layerMaskSection->layerCount; ++i)
		{
			// note that it is much easier to build the hierarchy by traversing the layers backwards
			Layer* layer = &layerMaskSection->layers[layerMaskSection->layerCount - i - 1u];

			PSD_ASSERT(stackIndex >= 0 && stackIndex < 256, "Stack index is out of bounds.");
			layer->parent = layerStack[stackIndex];

			unsigned int width = 0u;
			unsigned int height = 0u;
			GetExtents(layer, width, height);

			const bool isGroupStart = (layer->type == layerType::OPEN_FOLDER) || (layer->type == layerType::CLOSED_FOLDER);
			const bool isGroupEnd = (layer->type == layerType::SECTION_DIVIDER);
			if (isGroupEnd)
			{
				--stackIndex;
			}
			else if (isGroupStart)
			{
				++stackIndex;
				layerStack[stackIndex] = layer;
			}
		}
	}

	return layerMaskSection;
}


// ---------------------------------------------------------------------------------------------------------------------
// ---------------------------------------------------------------------------------------------------------------------
void ExtractLayer(const Document* document, File* file, Allocator* allocator, Layer* layer)
{
	PSD_ASSERT_NOT_NULL(file);
	PSD_ASSERT_NOT_NULL(allocator);
	PSD_ASSERT_NOT_NULL(layer);

	SyncFileReader reader(file);

	const unsigned int channelCount = layer->channelCount;
	for (unsigned int i=0; i < channelCount; ++i)
	{
		Channel* channel = &layer->channels[i];
		reader.SetPosition(channel->fileOffset);

		unsigned int width = 0u;
		unsigned int height = 0u;
		GetChannelExtents(layer, channel, width, height);

		// channel data is stored in 4 different formats, which is denoted by a 2-byte integer
		PSD_ASSERT(channel->data == nullptr, "Channel data has already been loaded.");
		const uint16_t compressionType = fileUtil::ReadFromFileBE<uint16_t>(reader);
		if (compressionType == compressionType::RAW)
		{
			if (document->bitsPerChannel == 8)
			{
				channel->data = ReadChannelDataRaw<uint8_t>(reader, allocator, width, height);
			}
			else if (document->bitsPerChannel == 16)
			{
				channel->data = ReadChannelDataRaw<uint16_t>(reader, allocator, width, height);
			}
			else if (document->bitsPerChannel == 32)
			{
				channel->data = ReadChannelDataRaw<float32_t>(reader, allocator, width, height);
			}
		}
		else if (compressionType == compressionType::RLE)
		{
			if (document->bitsPerChannel == 8)
			{
				channel->data = ReadChannelDataRLE<uint8_t>(reader, allocator, width, height);
			}
			else if (document->bitsPerChannel == 16)
			{
				channel->data = ReadChannelDataRLE<uint16_t>(reader, allocator, width, height);
			}
			else if (document->bitsPerChannel == 32)
			{
				channel->data = ReadChannelDataRLE<float32_t>(reader, allocator, width, height);
			}
		}
		else if (compressionType == compressionType::ZIP)
		{
			// note that we need to subtract 2 bytes from the channel data size because we already read the uint16_t
			// for the compression type.
			PSD_ASSERT(channel->size >= 2u, "Invalid channel data size %" PRIu64 ".", channel->size);
			const uint64_t channelDataSize = channel->size - 2u;
			if (document->bitsPerChannel == 8)
			{
				channel->data = ReadChannelDataZip<uint8_t>(reader, allocator, width, height, channelDataSize);
			}
			else if (document->bitsPerChannel == 16)
			{
				channel->data = ReadChannelDataZip<uint16_t>(reader, allocator, width, height, channelDataSize);
			}
			else if (document->bitsPerChannel == 32)
			{
				// note that this is NOT a bug.
				// in 32-bit mode, Photoshop always interprets ZIP compression as being ZIP_WITH_PREDICTION, presumably to get better compression when writing files.
				channel->data = ReadChannelDataZipPrediction<float32_t>(reader, allocator, width, height, channelDataSize);
			}
		}
		else if (compressionType == compressionType::ZIP_WITH_PREDICTION)
		{
			// note that we need to subtract 2 bytes from the channel data size because we already read the uint16_t
			// for the compression type.
			PSD_ASSERT(channel->size >= 2u, "Invalid channel data size %" PRIu64 ".", channel->size);
			const uint64_t channelDataSize = channel->size - 2u;
			if (document->bitsPerChannel == 8)
			{
				channel->data = ReadChannelDataZipPrediction<uint8_t>(reader, allocator, width, height, channelDataSize);
			}
			else if (document->bitsPerChannel == 16)
			{
				channel->data = ReadChannelDataZipPrediction<uint16_t>(reader, allocator, width, height, channelDataSize);
			}
			else if (document->bitsPerChannel == 32)
			{
				channel->data = ReadChannelDataZipPrediction<float32_t>(reader, allocator, width, height, channelDataSize);
			}
		}
		else
		{
			PSD_ASSERT(false, "Unsupported compression type %d", compressionType);
			return;
		}

		// if the channel doesn't have any data assigned to it, check if it is a mask channel of any kind.
		// layer masks sometimes don't have any planar data stored for them, because they are
		// e.g. pure black or white, which means they only get assigned a default color.
		if (!channel->data)
		{
			if (channel->type < 0)
			{
				// this is a layer mask, so create planar data for it
				const size_t dataSize = width * height * document->bitsPerChannel / 8u;
				void* channelData = allocator->Allocate(dataSize, 16u);
				memset(channelData, GetChannelDefaultColor(layer, channel), dataSize);
				channel->data = channelData;
			}
			else
			{
				// for layers like groups and group end markers ("</Layer group>") it is ok to not store any data
			}
		}
	}

	// now move channel data to our own data structures for layer and vector masks, invalidating the info stored in
	// that channel.
	for (unsigned int i=0; i < channelCount; ++i)
	{
		Channel* channel = &layer->channels[i];
		if (channel->type == channelType::LAYER_OR_VECTOR_MASK)
		{
			if (layer->vectorMask)
			{
				// layer has a vector mask, so this type always denotes the vector mask
				PSD_ASSERT(!layer->vectorMask->data, "Vector mask data has already been assigned.");
				MoveChannelToMask(channel, layer->vectorMask);
			}
			else if (layer->layerMask)
			{
				// we don't have a vector but a layer mask, so this type denotes the layer mask
				PSD_ASSERT(!layer->layerMask->data, "Layer mask data has already been assigned.");
				MoveChannelToMask(channel, layer->layerMask);
			}
			else
			{
				PSD_ASSERT(false, "The code failed to create a mask for this type internally. This should never happen.");
			}
		}
		else if (channel->type == channelType::LAYER_MASK)
		{
			PSD_ASSERT(layer->layerMask, "Layer mask must already exist.");
			PSD_ASSERT(!layer->layerMask->data, "Layer mask data has already been assigned.");
			MoveChannelToMask(channel, layer->layerMask);
		}
		else
		{
			// this channel is either a color channel, or the transparency mask. those should be stored in our channel array,
			// so there's nothing to do.
		}
	}
}


// ---------------------------------------------------------------------------------------------------------------------
// ---------------------------------------------------------------------------------------------------------------------
void DestroyLayerMaskSection(LayerMaskSection*& section, Allocator* allocator)
{
	PSD_ASSERT_NOT_NULL(section);
	PSD_ASSERT_NOT_NULL(allocator);

	for (unsigned int i=0; i < section->layerCount; ++i)
	{
		Layer* layer = &section->layers[i];
		for (unsigned int j=0; j < layer->channelCount; ++j)
		{
			Channel* channel = &layer->channels[j];
			allocator->Free(channel->data);
		}

		memoryUtil::FreeArray(allocator, layer->utf16Name);

		memoryUtil::FreeArray(allocator, layer->channels);

		if (layer->layerMask)
		{
			allocator->Free(layer->layerMask->data);
		}
		memoryUtil::Free(allocator, layer->layerMask);

		if (layer->vectorMask)
		{
			allocator->Free(layer->vectorMask->data);
		}
		memoryUtil::Free(allocator, layer->vectorMask);

		if (layer->smartObject)
		{
			if (layer->smartObject->file)
			{
				layer->smartObject->file->Close();
				layer->smartObject->file->~MemoryFile();
				allocator->Free(layer->smartObject->file);
			}
			allocator->Free(layer->smartObject->data);
		}
		memoryUtil::Free(allocator, layer->smartObject);
	}
	memoryUtil::FreeArray(allocator, section->layers);
	memoryUtil::Free(allocator, section);
}

PSD_NAMESPACE_END
