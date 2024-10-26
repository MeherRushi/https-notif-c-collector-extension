#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include "unyte_https_capabilities.h"

#include <sysrepo.h>


static void
print_val(const sr_val_t *value)
{
    if (NULL == value) {
        return;
    }

    printf("%s ", value->xpath);

    switch (value->type) {
    case SR_CONTAINER_T:
    case SR_CONTAINER_PRESENCE_T:
        printf("(container)");
        break;
    case SR_LIST_T:
        printf("(list instance)");
        break;
    case SR_STRING_T:
        printf("= %s", value->data.string_val);
        break;
    case SR_BOOL_T:
        printf("= %s", value->data.bool_val ? "true" : "false");
        break;
    case SR_DECIMAL64_T:
        printf("= %g", value->data.decimal64_val);
        break;
    case SR_INT8_T:
        printf("= %" PRId8, value->data.int8_val);
        break;
    case SR_INT16_T:
        printf("= %" PRId16, value->data.int16_val);
        break;
    case SR_INT32_T:
        printf("= %" PRId32, value->data.int32_val);
        break;
    case SR_INT64_T:
        printf("= %" PRId64, value->data.int64_val);
        break;
    case SR_UINT8_T:
        printf("= %" PRIu8, value->data.uint8_val);
        break;
    case SR_UINT16_T:
        printf("= %" PRIu16, value->data.uint16_val);
        break;
    case SR_UINT32_T:
        printf("= %" PRIu32, value->data.uint32_val);
        break;
    case SR_UINT64_T:
        printf("= %" PRIu64, value->data.uint64_val);
        break;
    case SR_IDENTITYREF_T:
        printf("= %s", value->data.identityref_val);
        break;
    case SR_INSTANCEID_T:
        printf("= %s", value->data.instanceid_val);
        break;
    case SR_BITS_T:
        printf("= %s", value->data.bits_val);
        break;
    case SR_BINARY_T:
        printf("= %s", value->data.binary_val);
        break;
    case SR_ENUM_T:
        printf("= %s", value->data.enum_val);
        break;
    case SR_LEAF_EMPTY_T:
        printf("(empty leaf)");
        break;
    default:
        printf("(unprintable)");
        break;
    }

    switch (value->type) {
    case SR_UNKNOWN_T:
    case SR_CONTAINER_T:
    case SR_CONTAINER_PRESENCE_T:
    case SR_LIST_T:
    case SR_LEAF_EMPTY_T:
        printf("\n");
        break;
    default:
        printf("%s\n", value->dflt ? " [default]" : "");
        break;
    }
}


unyte_https_capabilities_t *malloc_capabilities_buff(bool disable_json_encoding, bool disable_xml_encoding)
{
  unyte_https_capabilities_t *capabilities = (unyte_https_capabilities_t *)malloc(sizeof(unyte_https_capabilities_t));

  if (capabilities == NULL)
    return NULL;

  int json_capabilities_length = strlen(JSON_CAPABILITIES_START) + strlen(JSON_CAPABILITIES_END);
  int xml_capabilities_length = strlen(XML_CAPABILITIES_START) + strlen(XML_CAPABILITIES_END);

  if (!disable_xml_encoding)
  {
    json_capabilities_length += strlen(URN_ENCODING_XML) + 2; // 2 for the two ""
    xml_capabilities_length += strlen(XML_CAP_WRAPPER_START) + strlen(URN_ENCODING_XML) + strlen(XML_CAP_WRAPPER_END);
  }

  if (!disable_json_encoding)
  {
    if (!disable_xml_encoding)
      json_capabilities_length += 1;                           // 1 for the ","
    json_capabilities_length += strlen(URN_ENCODING_JSON) + 2; // 2 for the two ""
    xml_capabilities_length += strlen(XML_CAP_WRAPPER_START) + strlen(URN_ENCODING_JSON) + strlen(XML_CAP_WRAPPER_END);
  }

  capabilities->json = (char *)malloc(json_capabilities_length + 1); // 1 for \0
  capabilities->xml = (char *)malloc(xml_capabilities_length + 1);   // 1 for \0
  capabilities->json_length = json_capabilities_length;
  capabilities->xml_length = xml_capabilities_length;

  capabilities->enabled.json_encoding = false;
  capabilities->enabled.xml_encoding = false;
  return capabilities;
}

void add_xml_capability(unyte_https_capabilities_t *capabilities, int *json_it, int *xml_it)
{
  capabilities->json[*json_it] = '"';
  (*json_it)++;

  strcpy(capabilities->json + *json_it, URN_ENCODING_XML);
  (*json_it) += strlen(URN_ENCODING_XML);

  capabilities->json[*json_it] = '"';
  (*json_it)++;

  strcpy(capabilities->xml + *xml_it, XML_CAP_WRAPPER_START);
  (*xml_it) += strlen(XML_CAP_WRAPPER_START);
  strcpy(capabilities->xml + *xml_it, URN_ENCODING_XML);
  (*xml_it) += strlen(URN_ENCODING_XML);
  strcpy(capabilities->xml + *xml_it, XML_CAP_WRAPPER_END);
  (*xml_it) += strlen(XML_CAP_WRAPPER_END);
  
  capabilities->enabled.xml_encoding = true;
}

void add_json_capability(unyte_https_capabilities_t *capabilities, int *json_it, int *xml_it)
{

  capabilities->json[*json_it] = '"';
  (*json_it)++;

  strcpy(capabilities->json + *json_it, URN_ENCODING_JSON);
  (*json_it) += strlen(URN_ENCODING_JSON);

  capabilities->json[*json_it] = '"';
  (*json_it)++;

  strcpy(capabilities->xml + *xml_it, XML_CAP_WRAPPER_START);
  (*xml_it) += strlen(XML_CAP_WRAPPER_START);
  strcpy(capabilities->xml + *xml_it, URN_ENCODING_JSON);
  (*xml_it) += strlen(URN_ENCODING_JSON);
  strcpy(capabilities->xml + *xml_it, XML_CAP_WRAPPER_END);
  (*xml_it) += strlen(XML_CAP_WRAPPER_END);

  capabilities->enabled.json_encoding = true;
}

void check_json_xml_from_datastore(unyte_https_capabilities_t *capabilities, sr_val_t *vals, size_t val_count) {
  for (int i = 0; i < val_count; i++) {

    if (strcasestr(vals[i].xpath, URN_ENCODING_JSON) != NULL) {
      capabilities->enabled.json_encoding = true;
    }

    if (strcasestr(vals[i].xpath, URN_ENCODING_XML) != NULL) {
      capabilities->enabled.xml_encoding =  true;
    }

    // Exit early if both are true
    if(capabilities->enabled.json_encoding && capabilities->enabled.xml_encoding) {
      break;
    } 
  }

}


// Function to extract capability from each string in the list
char *extract_capability(const char *input) {
    const char *start = strstr(input, "='");
    const char *end = strstr(input, "']");
    if (start && end && end > start) {
        start += 2; // Move past "='"
        size_t len = end - start;

        // Allocate memory for the exact length of the substring + null terminator
        char *output = (char *)malloc(len + 1);
        if (output) {
            strncpy(output, start, len);
            output[len] = '\0';
        }
        return output;
    }
    return NULL;
}


// Function to calculate the total length needed for the XML format
int calculate_xml_length(const sr_val_t *vals, int size) {
    int total_length = strlen(XML_CAPABILITIES_START) + strlen(XML_CAPABILITIES_END);
    for (int i = 0; i < size; i++) {
        char *capability = extract_capability(vals[i].xpath);
        if (capability) {
            total_length += strlen(XML_CAP_WRAPPER_START) + strlen(capability) + strlen(XML_CAP_WRAPPER_END);
            free(capability);
        }
    }
    return total_length;
}

// Function to convert list of strings to XML format and store in buffer
void build_xml(const sr_val_t *vals, int size, unyte_https_capabilities_t *capabilities) {
    // Calculate total length needed
    capabilities->xml_length = calculate_xml_length(vals, size);

    // Allocate memory for the exact XML string length + null terminator
    capabilities->xml = (char *)malloc(capabilities->xml_length + 1);
    if (!capabilities->xml) {
        printf("Memory allocation for XML buffer failed.\n");
        return;
    }
    capabilities->xml[0] = '\0';  // Initialize the buffer to an empty string

    // Build the XML content
    strcat(capabilities->xml, XML_CAPABILITIES_START);
    for (int i = 0; i < size; i++) {
        char *capability = extract_capability(vals[i].xpath);
        if (capability) {
            strcat(capabilities->xml, XML_CAP_WRAPPER_START);
            strcat(capabilities->xml, capability);
            strcat(capabilities->xml, XML_CAP_WRAPPER_END);
            free(capability);
        }
    }
    strcat(capabilities->xml, XML_CAPABILITIES_END);
}

// Function to calculate the total length needed for the JSON format
int calculate_json_length(const sr_val_t *vals, int size) {
    int total_length = strlen(JSON_CAPABILITIES_START) + strlen(JSON_CAPABILITIES_END);
    for (int i = 0; i < size; i++) {
        char *capability = extract_capability(vals[i].xpath);
        if (capability) {
            total_length += strlen(capability) + 3; // 3 for quotes and comma
            free(capability);
        }
    }
    total_length -= 1; // Remove last comma
    return total_length;
}

// Function to convert list of strings to JSON format and store in buffer
void build_json(const sr_val_t *vals, int size, unyte_https_capabilities_t *capabilities) {
    // Calculate total length needed
    capabilities->json_length = calculate_json_length(vals, size);

    // Allocate memory for the exact JSON string length + null terminator
    capabilities->json = (char *)malloc(capabilities->json_length + 1);
    if (!capabilities->json) {
        printf("Memory allocation for JSON buffer failed.\n");
        return;
    }
    capabilities->json[0] = '\0'; // Initialize the buffer to an empty string

    // Build the JSON content
    strcat(capabilities->json, JSON_CAPABILITIES_START);
    for (int i = 0; i < size; i++) {
        char *capability = extract_capability(vals[i].xpath);
        if (capability) {
            strcat(capabilities->json, "\"");
            strcat(capabilities->json, capability);
            strcat(capabilities->json, "\"");
            if (i < size - 1) {
                strcat(capabilities->json, ",");
            }
            free(capability);
        }
    }
    strcat(capabilities->json, JSON_CAPABILITIES_END);
}


unyte_https_capabilities_t *reinit_capabilities_buff() {
  printf("DEBUG: entered reinit\n");

  //create a sysrepo connection and session
  sr_conn_ctx_t *connection = NULL;
  sr_session_ctx_t *session = NULL;
  sr_val_t *vals = NULL;
  size_t val_count = 0;
  int rc = SR_ERR_OK;
  const char *xpath, *value;
  //turns on logging, can be made optional by asking as an argument
  sr_log_stderr(SR_LL_WRN);

  rc = sr_connect(0, &connection);
  if(rc != SR_ERR_OK) {
    goto cleanup;
  }

  rc = sr_session_start(connection, SR_DS_RUNNING, &session);
  if (rc != SR_ERR_OK) {
    goto cleanup;
  }

  xpath = "/example:capabilities/*";
  rc = sr_get_items(session, xpath, 0, 0, &vals, &val_count);
  if (rc != SR_ERR_OK) {
    goto cleanup;
  }

  for(int i = 0; i < val_count; i++) {
    print_val(&vals[i]);
  }

  // Here we have read the values from the datastore as vals, 
  // now we have to figure out if the collector can support json, xml, both or none
  // based on the values read from the datastore - based on if the value is presnet or not
  // After that we need to parse the accept header and send the capabilities accordingly


  unyte_https_capabilities_t *capabilities = (unyte_https_capabilities_t *)malloc(sizeof(unyte_https_capabilities_t));

  if (capabilities == NULL){
     printf("Memory allocation for capabilities struct failed.\n");
     return NULL;
  }

    capabilities->json = NULL;
    capabilities->json_length = 0;
    capabilities->xml = NULL;
    capabilities->xml_length = 0;
    capabilities->enabled.json_encoding = false;
    capabilities->enabled.xml_encoding =  false;


  check_json_xml_from_datastore(capabilities, vals, val_count);
  
  printf("DEBUG: capabilities->enabled.json_encoding: %d\n", capabilities->enabled.json_encoding);
  printf("DEBUG: capabilities->enabled.xml_encoding: %d\n", capabilities->enabled.xml_encoding);

  // disable_json_encoding = !capabilities->enabled.json_encoding;
  // disable_xml_encoding = !capabilities->enabled.xml_encoding;

  if (!capabilities->enabled.json_encoding && !capabilities->enabled.xml_encoding) {
    printf("Cannot initialize capabilities ignoring all supported encodings. Enable one or more encodings\n");
    return NULL;
  }

  if(capabilities->enabled.xml_encoding) {
    //read the xml capability from the datastore
    // and assign to capabilities->xml and capabilities->xml_length
    printf("DEBUG: building xml\n");
    build_xml(vals, val_count, capabilities);
  }

  if(capabilities->enabled.json_encoding) {
    //read the json capability from the datastore
    // and assign to capabilities->json and capabilities->json_length
    printf("DEBUG: building json\n");
    build_json(vals, val_count, capabilities);
  }

  printf("DEBUG: capabilities->json: %s\n", capabilities->json);
  printf("DEBUG: capabilities->json_length: %d\n", capabilities->json_length);
  printf("DEBUG: capabilities->xml: %s\n", capabilities->xml);
  printf("DEBUG: capabilities->xml_length: %d\n", capabilities->xml_length);

  cleanup:
    sr_free_values(vals, val_count);
    sr_disconnect(connection);
    return rc ? NULL: capabilities ;
}

unyte_https_capabilities_t *init_capabilities_buff(bool disable_json_encoding, bool disable_xml_encoding)
{
  if (disable_json_encoding && disable_xml_encoding)
  {
    printf("Cannot initialize capabilities ignoring all supported encodings. Enable one or more encodings\n");
    return NULL;
  }
  unyte_https_capabilities_t *capabilities = malloc_capabilities_buff(disable_json_encoding, disable_xml_encoding);

  if (capabilities == NULL)
    return NULL;

  int json_it = strlen(JSON_CAPABILITIES_START);
  int xml_it = strlen(XML_CAPABILITIES_START);

  strcpy(capabilities->json, JSON_CAPABILITIES_START);
  strcpy(capabilities->xml, XML_CAPABILITIES_START);

  if (!disable_xml_encoding)
    add_xml_capability(capabilities, &json_it, &xml_it);

  if (!disable_json_encoding)
  {
    if (!disable_xml_encoding)
    {
      capabilities->json[json_it] = ',';
      json_it++;
    }
    add_json_capability(capabilities, &json_it, &xml_it);
  }

  strcpy(capabilities->json + json_it, JSON_CAPABILITIES_END);
  strcpy(capabilities->xml + xml_it, XML_CAPABILITIES_END);

  return capabilities;
}

void free_capabilities_buff(unyte_https_capabilities_t *capabilities)
{
  free(capabilities->json);
  free(capabilities->xml);
  free(capabilities);
}