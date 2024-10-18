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

unyte_https_capabilities_t *reinit_capabilities_buff(bool disable_json_encoding, bool disable_xml_encoding) {
    if (disable_json_encoding && disable_xml_encoding)
  {
    printf("Cannot initialize capabilities ignoring all supported encodings. Enable one or more encodings\n");
    return NULL;
  }
  unyte_https_capabilities_t *capabilities = malloc_capabilities_buff(disable_json_encoding, disable_xml_encoding);

  if (capabilities == NULL)
    return NULL;

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

  xpath = "/cont/l";
  rc = sr_get_items(session, xpath, 0, 0, &vals, &val_count);
  if (rc != SR_ERR_OK) {
    goto cleanup;
  }

  for(int i = 0; i < val_count; i++) {
    print_val(&vals[i]);
  }

  cleanup:
    sr_disconnect(connection);
    return rc ? EXIT_FAILURE : EXIT_SUCCESS;


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