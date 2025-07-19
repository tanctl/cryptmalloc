/**
 * @file test_serialization_enhanced.cpp
 * @brief comprehensive tests for enhanced serialization with version compatibility and type safety
 */

#include <catch2/catch_test_macros.hpp>
#include <memory>
#include <string>

#include "cryptmalloc/encrypted_types.hpp"
#include "cryptmalloc/bfv_context.hpp"

using namespace cryptmalloc;

// test fixture for serialization tests
class SerializationTestFixture {
public:
    std::shared_ptr<BFVContext> context;
    
    SerializationTestFixture() {
        auto params = BFVParameters{};
        params.security_level = SecurityLevel::HEStd_128_classic;
        params.ring_dimension = 8192;
        params.plaintext_modulus = 65537;
        params.multiplicative_depth = 2;
        params.batch_size = 4096;
        
        context = std::make_shared<BFVContext>(params);
        auto result = context->initialize();
        REQUIRE(result.has_value());
    }
};

TEST_CASE_METHOD(SerializationTestFixture, "Enhanced EncryptedSize serialization", "[serialization][encrypted_types][enhanced]") {
    SECTION("Version compatibility and type safety") {
        EncryptedSize size(1024, context);
        
        std::string serialized = size.serialize();
        
        // check version information
        REQUIRE(serialized.find("version:1") != std::string::npos);
        REQUIRE(serialized.find("type:size") != std::string::npos);
        REQUIRE(serialized.find("valid:true") != std::string::npos);
        
        // check integrity information
        REQUIRE(serialized.find("context_id:") != std::string::npos);
        REQUIRE(serialized.find("noise_budget:") != std::string::npos);
        REQUIRE(serialized.find("operations_count:") != std::string::npos);
        REQUIRE(serialized.find("size_range:") != std::string::npos);
    }
    
    SECTION("Successful deserialization with validation") {
        EncryptedSize original(2048, context);
        std::string serialized = original.serialize();
        
        auto deserialized = EncryptedSize::deserialize(serialized, context);
        REQUIRE(deserialized.has_value());
        REQUIRE(deserialized.value().is_valid());
    }
    
    SECTION("Version mismatch detection") {
        std::string invalid_version = "EncryptedSize{version:2,type:size,valid:true}";
        auto result = EncryptedSize::deserialize(invalid_version, context);
        REQUIRE_FALSE(result.has_value());
        REQUIRE(result.error().find("unsupported version") != std::string::npos);
    }
    
    SECTION("Type mismatch detection") {
        std::string wrong_type = "EncryptedSize{version:1,type:address,valid:true}";
        auto result = EncryptedSize::deserialize(wrong_type, context);
        REQUIRE_FALSE(result.has_value());
        REQUIRE(result.error().find("Type mismatch") != std::string::npos);
    }
    
    SECTION("Invalid object rejection") {
        std::string invalid_obj = "EncryptedSize{version:1,type:size,valid:false}";
        auto result = EncryptedSize::deserialize(invalid_obj, context);
        REQUIRE_FALSE(result.has_value());
        REQUIRE(result.error().find("Cannot deserialize invalid") != std::string::npos);
    }
    
    SECTION("Missing range validation") {
        std::string no_range = "EncryptedSize{version:1,type:size,valid:true}";
        auto result = EncryptedSize::deserialize(no_range, context);
        REQUIRE_FALSE(result.has_value());
        REQUIRE(result.error().find("Missing size range") != std::string::npos);
    }
}

TEST_CASE_METHOD(SerializationTestFixture, "Enhanced EncryptedAddress serialization", "[serialization][encrypted_types][enhanced]") {
    SECTION("Complete serialization metadata") {
        EncryptedAddress addr(0x2000, context);
        
        std::string serialized = addr.serialize();
        
        // check all required fields
        REQUIRE(serialized.find("version:1") != std::string::npos);
        REQUIRE(serialized.find("type:address") != std::string::npos);
        REQUIRE(serialized.find("valid:true") != std::string::npos);
        REQUIRE(serialized.find("context_id:") != std::string::npos);
        REQUIRE(serialized.find("noise_budget:") != std::string::npos);
        REQUIRE(serialized.find("operations_count:") != std::string::npos);
        REQUIRE(serialized.find("address_range:") != std::string::npos);
    }
    
    SECTION("Address range validation during deserialization") {
        EncryptedAddress original(0x1000, context);
        std::string serialized = original.serialize();
        
        auto deserialized = EncryptedAddress::deserialize(serialized, context);
        REQUIRE(deserialized.has_value());
        REQUIRE(deserialized.value().is_valid());
    }
    
    SECTION("Missing address range rejection") {
        std::string no_range = "EncryptedAddress{version:1,type:address,valid:true}";
        auto result = EncryptedAddress::deserialize(no_range, context);
        REQUIRE_FALSE(result.has_value());
        REQUIRE(result.error().find("Missing address range") != std::string::npos);
    }
}

TEST_CASE_METHOD(SerializationTestFixture, "Enhanced EncryptedPointer serialization", "[serialization][encrypted_types][enhanced]") {
    SECTION("Comprehensive metadata serialization") {
        EncryptedAddress addr(0x4000, context);
        PointerMetadata metadata;
        metadata.element_size = 8;
        metadata.array_length = 10;
        metadata.alignment = 8;
        metadata.is_array = true;
        metadata.is_valid = true;
        metadata.type_name = "test_type";
        
        EncryptedPointer ptr(addr, metadata);
        std::string serialized = ptr.serialize();
        
        // check version and type info
        REQUIRE(serialized.find("version:1") != std::string::npos);
        REQUIRE(serialized.find("type:pointer") != std::string::npos);
        
        // check metadata preservation
        REQUIRE(serialized.find("element_size:8") != std::string::npos);
        REQUIRE(serialized.find("array_length:10") != std::string::npos);
        REQUIRE(serialized.find("alignment:8") != std::string::npos);
        REQUIRE(serialized.find("is_array:true") != std::string::npos);
        REQUIRE(serialized.find("is_valid:true") != std::string::npos);
        REQUIRE(serialized.find("type_name:\"test_type\"") != std::string::npos);
        REQUIRE(serialized.find("consistent:true") != std::string::npos);
        
        // check address data inclusion
        REQUIRE(serialized.find("address_data:") != std::string::npos);
    }
    
    SECTION("Metadata consistency validation") {
        std::string inconsistent = "EncryptedPointer{version:1,type:pointer,consistent:false}";
        auto result = EncryptedPointer::deserialize(inconsistent, context);
        REQUIRE_FALSE(result.has_value());
        REQUIRE(result.error().find("Inconsistent metadata") != std::string::npos);
    }
    
    SECTION("Successful deserialization with generated metadata") {
        EncryptedAddress addr(0x8000, context);
        PointerMetadata metadata;
        metadata.element_size = 4;
        metadata.array_length = 5;
        metadata.alignment = 4;
        metadata.is_array = false;
        metadata.is_valid = true;
        metadata.type_name = "int32_t";
        
        EncryptedPointer original(addr, metadata);
        std::string serialized = original.serialize();
        
        auto deserialized = EncryptedPointer::deserialize(serialized, context);
        REQUIRE(deserialized.has_value());
        REQUIRE(deserialized.value().is_valid());
        
        // check that deserialized metadata is consistent
        const auto& meta = deserialized.value().metadata();
        REQUIRE(meta.is_consistent());
        REQUIRE(meta.is_valid);
        REQUIRE(meta.type_name == "deserialized_pointer");
    }
}

TEST_CASE_METHOD(SerializationTestFixture, "Cross-type serialization safety", "[serialization][encrypted_types][safety]") {
    SECTION("Cannot deserialize wrong type") {
        EncryptedSize size(512, context);
        std::string size_data = size.serialize();
        
        // try to deserialize as address
        auto addr_result = EncryptedAddress::deserialize(size_data, context);
        REQUIRE_FALSE(addr_result.has_value());
        REQUIRE(addr_result.error().find("Type mismatch") != std::string::npos);
        
        // try to deserialize as pointer
        auto ptr_result = EncryptedPointer::deserialize(size_data, context);
        REQUIRE_FALSE(ptr_result.has_value());
        REQUIRE(ptr_result.error().find("Type mismatch") != std::string::npos);
    }
    
    SECTION("Malformed data rejection") {
        std::vector<std::string> invalid_data = {
            "",
            "garbage",
            "EncryptedSize{",
            "SomeOtherType{version:1}",
            "EncryptedSize{version:1}"  // missing required fields
        };
        
        for (const auto& data : invalid_data) {
            auto size_result = EncryptedSize::deserialize(data, context);
            REQUIRE_FALSE(size_result.has_value());
            
            auto addr_result = EncryptedAddress::deserialize(data, context);
            REQUIRE_FALSE(addr_result.has_value());
            
            auto ptr_result = EncryptedPointer::deserialize(data, context);
            REQUIRE_FALSE(ptr_result.has_value());
        }
    }
}

TEST_CASE_METHOD(SerializationTestFixture, "Serialization performance characteristics", "[serialization][encrypted_types][performance]") {
    SECTION("Serialization produces reasonable data sizes") {
        EncryptedSize size(1024, context);
        EncryptedAddress addr(0x2000, context);
        
        std::string size_data = size.serialize();
        std::string addr_data = addr.serialize();
        
        // serialized data should be informative but not excessive
        REQUIRE(size_data.length() > 50);  // has meaningful content
        REQUIRE(size_data.length() < 500); // not excessive
        
        REQUIRE(addr_data.length() > 50);
        REQUIRE(addr_data.length() < 500);
        
        // pointer serialization includes more metadata
        EncryptedAddress ptr_addr(0x4000, context);
        PointerMetadata metadata;
        metadata.element_size = 16;
        metadata.array_length = 100;
        metadata.alignment = 16;
        metadata.is_array = true;
        metadata.is_valid = true;
        metadata.type_name = "large_structure";
        
        EncryptedPointer ptr(ptr_addr, metadata);
        std::string ptr_data = ptr.serialize();
        
        REQUIRE(ptr_data.length() > 100);  // more metadata
        REQUIRE(ptr_data.length() < 1000); // still reasonable
    }
}