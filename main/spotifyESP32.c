#include <stdio.h>
#include <string.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/semphr.h"
#include "mbedtls/base64.h"

#include "esp_log.h"
#include "esp_wifi.h"
#include "esp_http_client.h"
#include "esp_event.h"
#include "nvs_flash.h"
#include "cJSON.h"
#include "esp_crt_bundle.h"

#define WIFI_SSID "Mint"
#define WIFI_PASS "9876543210"
#define CLIENT_ID "977cb33459a34c2db2b2d2186b4c2462" // Replace with your actual CLIENT_ID
#define CLIENT_SECRET "b0ab7e1e7cf743ca969b858752ca5681" // Replace with your actual CLIENT_SECRET

static const char *WIFI_TAG = "wifi_only";
static const char *SPOTIFY_TAG = "spotify_api";

SemaphoreHandle_t wifiSemaphore;

// Global buffer for HTTP response from both token and API calls
#define MAX_HTTP_RESPONSE_BUFFER 2048 // Increased buffer for API responses
static char http_response_buffer[MAX_HTTP_RESPONSE_BUFFER];
static int http_response_len = 0;

// Global variable to store the access token
#define MAX_ACCESS_TOKEN_LENGTH 512
static char spotify_access_token[MAX_ACCESS_TOKEN_LENGTH] = {0};

// --- HTTP Event Handler ---
esp_err_t _http_event_handler(esp_http_client_event_t *evt) {
    switch(evt->event_id) {
        case HTTP_EVENT_ON_DATA:
            if (evt->data_len + http_response_len < MAX_HTTP_RESPONSE_BUFFER) {
                memcpy(http_response_buffer + http_response_len, evt->data, evt->data_len);
                http_response_len += evt->data_len;
            } else {
                ESP_LOGE(SPOTIFY_TAG, "HTTP response buffer overflow! Data truncated.");
                int remaining_space = MAX_HTTP_RESPONSE_BUFFER - http_response_len;
                if (remaining_space > 0) {
                    memcpy(http_response_buffer + http_response_len, evt->data, remaining_space);
                    http_response_len += remaining_space;
                }
            }
            break;
        case HTTP_EVENT_ON_FINISH:
            if (http_response_len < MAX_HTTP_RESPONSE_BUFFER) {
                http_response_buffer[http_response_len] = '\0';
            } else {
                http_response_buffer[MAX_HTTP_RESPONSE_BUFFER - 1] = '\0';
            }
            ESP_LOGD(SPOTIFY_TAG, "HTTP_EVENT_ON_FINISH. Total collected: %d bytes", http_response_len);
            break;
        case HTTP_EVENT_ERROR:
        case HTTP_EVENT_ON_CONNECTED:
        case HTTP_EVENT_HEADER_SENT:
        case HTTP_EVENT_ON_HEADER:
        case HTTP_EVENT_DISCONNECTED:
        case HTTP_EVENT_REDIRECT:
            break;
    }
    return ESP_OK;
}
// --- END HTTP Event Handler ---


static void wifi_event_handler(void *arg, esp_event_base_t event_base,
                               int32_t event_id, void *event_data) {
    if (event_id == WIFI_EVENT_STA_START) {
        ESP_LOGI(WIFI_TAG, "Wi-Fi starting...");
        esp_wifi_connect();
    } else if (event_id == WIFI_EVENT_STA_DISCONNECTED) {
        ESP_LOGW(WIFI_TAG, "Disconnected. Reconnecting...");
        esp_wifi_connect();
    }
}

static void ip_event_handler(void *arg, esp_event_base_t event_base,
                             int32_t event_id, void *event_data) {
    if (event_id == IP_EVENT_STA_GOT_IP) {
        ESP_LOGI(WIFI_TAG, "Got IP address!");
        xSemaphoreGive(wifiSemaphore);
    }
}

void parse_spotify_token(const char *json_str) {
    if (json_str == NULL || strlen(json_str) == 0) {
        ESP_LOGE("JSON", "Cannot parse empty or NULL JSON string.");
        return;
    }

    cJSON *root = cJSON_Parse(json_str);
    if (root == NULL) {
        const char *error_ptr = cJSON_GetErrorPtr();
        if (error_ptr != NULL) {
            ESP_LOGE("JSON", "Failed to parse JSON: Error before %s. String: '%s'", error_ptr, json_str);
        } else {
            ESP_LOGE("JSON", "Failed to parse JSON (unknown error). String: '%s'", json_str);
        }
        return;
    }

    const cJSON *access_token = cJSON_GetObjectItem(root, "access_token");
    if (cJSON_IsString(access_token) && (access_token->valuestring != NULL)) {
        ESP_LOGI("JSON", "Access Token: %s", access_token->valuestring);
        strncpy(spotify_access_token, access_token->valuestring, MAX_ACCESS_TOKEN_LENGTH - 1);
        spotify_access_token[MAX_ACCESS_TOKEN_LENGTH - 1] = '\0';
    } else {
        ESP_LOGE("JSON", "access_token not found or invalid");
    }

    const cJSON *expires_in = cJSON_GetObjectItem(root, "expires_in");
    if (cJSON_IsNumber(expires_in)) {
        ESP_LOGI("JSON", "Expires in: %d seconds", expires_in->valueint);
    } else {
        ESP_LOGW("JSON", "expires_in not found or invalid");
    }

    const cJSON *error_obj = cJSON_GetObjectItem(root, "error");
    const cJSON *error_description_obj = cJSON_GetObjectItem(root, "error_description");

    if (cJSON_IsString(error_obj) && cJSON_IsString(error_description_obj)) {
        ESP_LOGE("JSON", "Spotify API Error: %s - %s", error_obj->valuestring, error_description_obj->valuestring);
    }

    cJSON_Delete(root);
}

void get_spotify_token() {
    // Spotify Accounts Service Token Endpoint
    const char *url = "https://accounts.spotify.com/api/token";

    http_response_len = 0;
    memset(http_response_buffer, 0, MAX_HTTP_RESPONSE_BUFFER);

    const char *post_data = "grant_type=client_credentials";

    char credentials[128];
    snprintf(credentials, sizeof(credentials), "%s:%s", CLIENT_ID, CLIENT_SECRET);

    unsigned char encoded[256];
    size_t encoded_len = 0;
    int ret_b64 = mbedtls_base64_encode(encoded, sizeof(encoded), &encoded_len, (const unsigned char *)credentials, strlen(credentials));
    if (ret_b64 != 0) {
        ESP_LOGE(SPOTIFY_TAG, "Base64 encoding failed: %d", ret_b64);
        return;
    }
    encoded[encoded_len] = '\0';

    char auth_header[300];
    snprintf(auth_header, sizeof(auth_header), "Basic %s", encoded);

    esp_http_client_config_t config = {
        .url = url,
        .method = HTTP_METHOD_POST,
        .transport_type = HTTP_TRANSPORT_OVER_SSL,
        .crt_bundle_attach = esp_crt_bundle_attach,
        .event_handler = _http_event_handler,
        .timeout_ms = 10000,
    };

    esp_http_client_handle_t client = esp_http_client_init(&config);
    if (client == NULL) {
        ESP_LOGE(SPOTIFY_TAG, "Failed to initialize HTTP client");
        return;
    }

    esp_http_client_set_header(client, "Content-Type", "application/x-www-form-urlencoded");
    esp_http_client_set_header(client, "Authorization", auth_header);
    esp_http_client_set_header(client, "Accept-Encoding", "identity");

    esp_http_client_set_post_field(client, post_data, strlen(post_data));

    esp_err_t err = esp_http_client_perform(client);
    if (err == ESP_OK) {
        int status = esp_http_client_get_status_code(client);
        ESP_LOGI(SPOTIFY_TAG, "Token Request HTTPS Status = %d", status);

        if (status == 200 && http_response_len > 0) {
            ESP_LOGI(SPOTIFY_TAG, "Token Response (len=%d): %s", http_response_len, http_response_buffer);
            parse_spotify_token(http_response_buffer);
        } else if (status != 200) {
            ESP_LOGE(SPOTIFY_TAG, "Token request failed with status code %d.", status);
            if (http_response_len > 0) {
                ESP_LOGE(SPOTIFY_TAG, "Token Error Response Body: %s", http_response_buffer);
                parse_spotify_token(http_response_buffer);
            } else {
                ESP_LOGE(SPOTIFY_TAG, "No token error response body received for status %d", status);
            }
        } else {
            ESP_LOGE(SPOTIFY_TAG, "Token request successful but no content (Status %d, Length %d)", status, http_response_len);
        }
    } else {
        ESP_LOGE(SPOTIFY_TAG, "Token HTTP request failed: %s", esp_err_to_name(err));
    }

    esp_http_client_cleanup(client);
}

// --- NEW FUNCTION: Get Spotify Artist Data ---
void get_spotify_artist_data(const char* artist_id) {
    if (strlen(spotify_access_token) == 0) {
        ESP_LOGE(SPOTIFY_TAG, "No access token available. Cannot get artist data.");
        return;
    }

    // Spotify Web API Base Endpoint - This is correct!
    const char *base_api_url = "https://api.spotify.com";
    char url_buffer[512]; // Buffer for the full URL

    // Construct the URL for the Get Artist endpoint: https://api.spotify.com/v1/artists/{id}
    snprintf(url_buffer, sizeof(url_buffer), "%s/v1/artists/%s", base_api_url, artist_id);
    ESP_LOGI(SPOTIFY_TAG, "Artist API URL: %s", url_buffer); // Log the constructed URL for debugging

    http_response_len = 0;
    memset(http_response_buffer, 0, MAX_HTTP_RESPONSE_BUFFER);

    char auth_header[MAX_ACCESS_TOKEN_LENGTH + 10]; // "Bearer " + token + '\0'
    snprintf(auth_header, sizeof(auth_header), "Bearer %s", spotify_access_token);

    esp_http_client_config_t config = {
        .url = url_buffer, // Use the constructed URL
        .method = HTTP_METHOD_GET, // GET method for fetching data
        .transport_type = HTTP_TRANSPORT_OVER_SSL,
        .crt_bundle_attach = esp_crt_bundle_attach,
        .event_handler = _http_event_handler,
        .timeout_ms = 15000,
    };

    esp_http_client_handle_t client = esp_http_client_init(&config);
    if (client == NULL) {
        ESP_LOGE(SPOTIFY_TAG, "Failed to initialize HTTP client for Artist API call");
        return;
    }

    esp_http_client_set_header(client, "Authorization", auth_header);
    esp_http_client_set_header(client, "Accept", "application/json"); // Request JSON response
    // REMOVED: esp_http_client_set_header(client, "Host", "api.spotify.com"); // Let esp_http_client set this automatically

    esp_err_t err = esp_http_client_perform(client);
    if (err == ESP_OK) {
        int status = esp_http_client_get_status_code(client);
        ESP_LOGI(SPOTIFY_TAG, "Artist API Request HTTPS Status = %d", status);

        if (status == 200 && http_response_len > 0) {
            ESP_LOGI(SPOTIFY_TAG, "Artist API Response (len=%d): %s", http_response_len, http_response_buffer);
            // In a real application, you would parse this JSON to extract artist details
            // For now, we're just logging the full response.
        } else if (status != 200) {
            ESP_LOGE(SPOTIFY_TAG, "Artist API request failed with status code %d.", status);
            if (http_response_len > 0) {
                ESP_LOGE(SPOTIFY_TAG, "Artist API Error Response Body: %s", http_response_buffer);
            } else {
                ESP_LOGE(SPOTIFY_TAG, "No artist API error response body received for status %d", status);
            }
        } else {
            ESP_LOGE(SPOTIFY_TAG, "Artist API request successful but no content (Status %d, Length %d)", status, http_response_len);
        }
    } else {
        ESP_LOGE(SPOTIFY_TAG, "Artist API HTTP request failed: %s", esp_err_to_name(err));
    }

    esp_http_client_cleanup(client);
}


void spotify_task(void *pvParameters) {
    get_spotify_token(); // First, get the token

    // Only proceed to make API calls if a token was successfully obtained
    if (strlen(spotify_access_token) > 0) {
        vTaskDelay(pdMS_TO_TICKS(1000)); // Give some time after token request

        // --- Make a sample API call: Get Artist Data ---
        // Using Queen's Spotify Artist ID
        get_spotify_artist_data("1dfeR4HaWDbWqFHLkxsg1d");

        // You could add other API calls here if needed, or loop with delays
    } else {
        ESP_LOGE(SPOTIFY_TAG, "Failed to obtain Spotify access token. Cannot proceed with API calls.");
    }

    vTaskDelete(NULL); // Task self-deletes after execution
}

void app_main(void) {
    esp_err_t ret = nvs_flash_init();
    if (ret == ESP_ERR_NVS_NO_FREE_PAGES || ret == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_ERROR_CHECK(nvs_flash_erase());
        ret = nvs_flash_init();
    }
    ESP_ERROR_CHECK(ret);

    ESP_ERROR_CHECK(esp_netif_init());
    ESP_ERROR_CHECK(esp_event_loop_create_default());

    esp_netif_create_default_wifi_sta();

    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_wifi_init(&cfg));

    wifiSemaphore = xSemaphoreCreateBinary();

    esp_event_handler_instance_t mWifiEvent;
    esp_event_handler_instance_t mIpEvent;

    ESP_ERROR_CHECK(esp_event_handler_instance_register(WIFI_EVENT, ESP_EVENT_ANY_ID, &wifi_event_handler, NULL, &mWifiEvent));
    ESP_ERROR_CHECK(esp_event_handler_instance_register(IP_EVENT, IP_EVENT_STA_GOT_IP, &ip_event_handler, NULL, &mIpEvent));

    wifi_config_t wifi_config = {
        .sta = {
            .ssid = WIFI_SSID,
            .password = WIFI_PASS
        },
    };
    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA));
    ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_STA, &wifi_config));
    ESP_ERROR_CHECK(esp_wifi_start());

    ESP_LOGI(WIFI_TAG, "Wi-Fi init done");
    ESP_LOGI(WIFI_TAG, "Waiting for IP...");

    xSemaphoreTake(wifiSemaphore, portMAX_DELAY);
    ESP_LOGI(WIFI_TAG, "Connected to Wi-Fi successfully!");

    xTaskCreate(spotify_task, "spotify_task", 8192, NULL, 5, NULL);
}