#include <stdio.h>
#include <string.h>
#include <freertos/FreeRTOS.h>
#include <freertos/task.h>
#include <freertos/event_groups.h>
#include <esp_log.h>
#include <nvs_flash.h>
#include <esp_wifi.h>
#include <esp_http_client.h>
#include <cJSON.h>
#include <mbedtls/sha256.h>
#include <mbedtls/base64.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>
#include "esp_event.h"
#include "esp_netif.h"
#include "driver/uart.h"
#include "esp_crt_bundle.h" // Include the certificate bundle for TLS verification

// --- CONFIGURATION ---
// You MUST replace these with your actual credentials from the Spotify Developer Dashboard.
// NOTE: The redirect URI must be configured in your Spotify Developer Dashboard.
#define WIFI_SSID                "Mint"
#define WIFI_PASS                "9876543210"
#define SPOTIFY_CLIENT_ID        "977cb33459a34c2db2b2d2186b4c2462"
// Use a standard HTTP redirect URI for a reliable local callback.
#define SPOTIFY_REDIRECT_URI     "http://127.0.0.1:8888/callback"
// Define the Spotify API scopes required by your application.
#define SPOTIFY_SCOPE            "user-read-currently-playing user-modify-playback-state"

#define PKCE_CODE_VERIFIER_LEN   128
#define PKCE_CODE_CHALLENGE_LEN  64
// FIX: Increased the buffer size to handle larger API responses from Spotify.
// The "currently playing" endpoint can return a large JSON object.
#define MAX_HTTP_OUTPUT_BUFFER   8192
// Increased buffer size for the authorization code to prevent overflow.
#define MAX_AUTH_CODE_LEN        512

static const char *TAG = "SPOTIFY_AUTH";

// Event group to signal when Wi-Fi is connected and an IP address is obtained.
static EventGroupHandle_t wifi_event_group;
const int CONNECTED_BIT = BIT0;

// Global variables to store the access and refresh tokens.
static char g_access_token[256] = {0};
static char g_refresh_token[256] = {0};
// Global variable to store the PKCE code verifier, needed for the token exchange.
static char g_code_verifier[PKCE_CODE_VERIFIER_LEN + 1] = {0};

// Pointers for the HTTP response buffer and its size.
static char *http_response_buffer = NULL;
static int http_response_buffer_len = 0;

/**
 * @brief HTTP event handler for processing responses.
 * @param evt The event structure.
 * @return ESP_OK on success, ESP_FAIL on failure.
 */
esp_err_t _http_event_handler(esp_http_client_event_t *evt) {
    switch(evt->event_id) {
        case HTTP_EVENT_ON_CONNECTED:
            ESP_LOGI(TAG, "HTTP_EVENT_ON_CONNECTED");
            break;
        case HTTP_EVENT_HEADER_SENT:
            ESP_LOGI(TAG, "HTTP_EVENT_HEADER_SENT");
            break;
        case HTTP_EVENT_ON_HEADER:
            ESP_LOGD(TAG, "HTTP_EVENT_ON_HEADER, key=%s, value=%s", evt->header_key, evt->header_value);
            break;
        case HTTP_EVENT_ON_DATA:
            ESP_LOGD(TAG, "HTTP_EVENT_ON_DATA, len=%d", evt->data_len);
            // Append data to the buffer.
            if (http_response_buffer == NULL) {
                http_response_buffer = (char *)malloc(MAX_HTTP_OUTPUT_BUFFER);
                http_response_buffer_len = 0;
                if (!http_response_buffer) {
                    ESP_LOGE(TAG, "Failed to allocate memory for output buffer");
                    return ESP_FAIL;
                }
            }
            if (http_response_buffer_len + evt->data_len < MAX_HTTP_OUTPUT_BUFFER) {
                memcpy(http_response_buffer + http_response_buffer_len, evt->data, evt->data_len);
                http_response_buffer_len += evt->data_len;
            } else {
                ESP_LOGE(TAG, "Output buffer overflow");
            }
            break;
        case HTTP_EVENT_ON_FINISH:
            ESP_LOGI(TAG, "HTTP_EVENT_ON_FINISH");
            if (http_response_buffer != NULL) {
                http_response_buffer[http_response_buffer_len] = '\0';
                ESP_LOGI(TAG, "Total content length: %d", http_response_buffer_len);
                
                // --- FIX: Correctly get the URL and store it in a buffer. ---
                char current_url[256];
                if (esp_http_client_get_url(evt->client, current_url, sizeof(current_url)) == ESP_OK) {
                    // Parse the JSON response based on the URL to handle different API calls.
                    if (strstr(current_url, "api/token") != NULL) {
                        // This is a token response.
                        cJSON *root = cJSON_Parse(http_response_buffer);
                        if (root == NULL) {
                            ESP_LOGE(TAG, "Failed to parse JSON response for token");
                        } else {
                            cJSON *access_token = cJSON_GetObjectItem(root, "access_token");
                            cJSON *refresh_token = cJSON_GetObjectItem(root, "refresh_token");
                            
                            if (cJSON_IsString(access_token) && access_token->valuestring != NULL) {
                                snprintf(g_access_token, sizeof(g_access_token), "%s", access_token->valuestring);
                            }
                            if (cJSON_IsString(refresh_token) && refresh_token->valuestring != NULL) {
                                snprintf(g_refresh_token, sizeof(g_refresh_token), "%s", refresh_token->valuestring);
                            }
                            cJSON_Delete(root);
                        }
                    } else if (strstr(current_url, "currently-playing") != NULL) {
                        // This is a "currently playing" song response.
                        cJSON *root = cJSON_Parse(http_response_buffer);
                        if (root == NULL) {
                            ESP_LOGE(TAG, "Failed to parse JSON response for currently playing");
                        } else {
                            cJSON *is_playing = cJSON_GetObjectItem(root, "is_playing");
                            if (cJSON_IsTrue(is_playing)) {
                                cJSON *item = cJSON_GetObjectItem(root, "item");
                                cJSON *album = cJSON_GetObjectItem(item, "album");
                                cJSON *artists_array = cJSON_GetObjectItem(item, "artists");
                                
                                char *track_name = cJSON_GetObjectItem(item, "name")->valuestring;
                                char *artist_name = cJSON_GetObjectItem(cJSON_GetArrayItem(artists_array, 0), "name")->valuestring;
                                char *album_name = cJSON_GetObjectItem(album, "name")->valuestring;
                                
                                ESP_LOGI(TAG, "Currently Playing: %s by %s (from album: %s)", track_name, artist_name, album_name);
                            } else {
                                ESP_LOGI(TAG, "No song is currently playing.");
                            }
                            cJSON_Delete(root);
                        }
                    }
                } else {
                    ESP_LOGE(TAG, "Failed to get URL from client handle.");
                }
                
                free(http_response_buffer);
                http_response_buffer = NULL;
            }
            http_response_buffer_len = 0;
            break;
        case HTTP_EVENT_DISCONNECTED:
            ESP_LOGI(TAG, "HTTP_EVENT_DISCONNECTED");
            break;
        default:
            break;
    }
    return ESP_OK;
}

/**
 * @brief Generates the PKCE code verifier and challenge.
 * The code verifier is a random string, and the code challenge is its URL-safe base64-encoded SHA256 hash.
 * @param code_challenge A buffer to store the generated code challenge.
 */
void generate_pkce_codes(char *code_challenge) {
    // Generate a random string for the code verifier.
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);
    mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, NULL, 0);

    const char *possible_chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~";
    
    // The PKCE spec requires a length between 43 and 128. We use the maximum.
    for (int i = 0; i < PKCE_CODE_VERIFIER_LEN; i++) {
        uint8_t rand_byte;
        mbedtls_ctr_drbg_random(&ctr_drbg, &rand_byte, 1);
        g_code_verifier[i] = possible_chars[rand_byte % 66];
    }
    g_code_verifier[PKCE_CODE_VERIFIER_LEN] = '\0';
    
    ESP_LOGI(TAG, "Generated Code Verifier: %s", g_code_verifier);

    // Hash the code verifier using SHA256.
    unsigned char hash[32]; // SHA256 produces a 32-byte hash.
    mbedtls_sha256((const unsigned char *)g_code_verifier, strlen(g_code_verifier), hash, 0);

    // Base64 encode the hash to create the code challenge.
    size_t output_len;
    mbedtls_base64_encode((unsigned char *)code_challenge, PKCE_CODE_CHALLENGE_LEN, &output_len, hash, 32);

    // Convert to a Base64 URL-safe string by replacing characters and removing padding.
    for (int i = 0; i < output_len; i++) {
        if (code_challenge[i] == '+') {
            code_challenge[i] = '-';
        } else if (code_challenge[i] == '/') {
            code_challenge[i] = '_';
        } else if (code_challenge[i] == '=') {
            code_challenge[i] = '\0'; // Remove padding characters.
            output_len = i;
            break;
        }
    }
    code_challenge[output_len] = '\0';
    ESP_LOGI(TAG, "Generated Code Challenge: %s", code_challenge);
}

/**
 * @brief Exchanges the authorization code for access and refresh tokens.
 * @param auth_code The authorization code received from the user.
 */
void exchange_code_for_token(const char *auth_code) {
    ESP_LOGI(TAG, "Exchanging authorization code for tokens...");
    esp_http_client_config_t config = {
        .url = "https://accounts.spotify.com/api/token",
        .event_handler = _http_event_handler,
        .crt_bundle_attach = esp_crt_bundle_attach, // Use the root certificate bundle for verification.
    };
    esp_http_client_handle_t client = esp_http_client_init(&config);
    esp_http_client_set_method(client, HTTP_METHOD_POST);
    esp_http_client_set_header(client, "Content-Type", "application/x-www-form-urlencoded");

    // Construct the POST request body.
    char post_data[MAX_AUTH_CODE_LEN + 256];
    snprintf(post_data, sizeof(post_data),
             "grant_type=authorization_code&code=%s&redirect_uri=%s&client_id=%s&code_verifier=%s",
             auth_code, SPOTIFY_REDIRECT_URI, SPOTIFY_CLIENT_ID, g_code_verifier);
    esp_http_client_set_post_field(client, post_data, strlen(post_data));

    esp_err_t err = esp_http_client_perform(client);
    if (err == ESP_OK) {
        ESP_LOGI(TAG, "HTTP POST Status = %d, content_length = %lld",
                 esp_http_client_get_status_code(client),
                 esp_http_client_get_content_length(client));
    } else {
        ESP_LOGE(TAG, "HTTP POST request failed: %s", esp_err_to_name(err));
    }

    esp_http_client_cleanup(client);
}

/**
 * @brief Refreshes the access token using the stored refresh token.
 */
void refresh_access_token() {
    ESP_LOGI(TAG, "Refreshing access token...");
    esp_http_client_config_t config = {
        .url = "https://accounts.spotify.com/api/token",
        .event_handler = _http_event_handler,
        .crt_bundle_attach = esp_crt_bundle_attach,
    };
    esp_http_client_handle_t client = esp_http_client_init(&config);
    esp_http_client_set_method(client, HTTP_METHOD_POST);
    esp_http_client_set_header(client, "Content-Type", "application/x-www-form-urlencoded");

    char post_data[512];
    snprintf(post_data, sizeof(post_data),
             "grant_type=refresh_token&refresh_token=%s&client_id=%s",
             g_refresh_token, SPOTIFY_CLIENT_ID);
    esp_http_client_set_post_field(client, post_data, strlen(post_data));

    esp_err_t err = esp_http_client_perform(client);
    if (err == ESP_OK) {
        ESP_LOGI(TAG, "Refresh Token POST Status = %d", esp_http_client_get_status_code(client));
    } else {
        ESP_LOGE(TAG, "Refresh Token POST request failed: %s", esp_err_to_name(err));
    }

    esp_http_client_cleanup(client);
}

/**
 * @brief Makes a GET request to the Spotify API to get the currently playing song.
 */
void get_currently_playing_song() {
    ESP_LOGI(TAG, "Fetching currently playing song...");
    char url[128];
    snprintf(url, sizeof(url), "https://api.spotify.com/v1/me/player/currently-playing");
    
    esp_http_client_config_t config = {
        .url = url,
        .event_handler = _http_event_handler,
        .crt_bundle_attach = esp_crt_bundle_attach,
    };
    esp_http_client_handle_t client = esp_http_client_init(&config);
    esp_http_client_set_method(client, HTTP_METHOD_GET);
    
    // Set the Authorization header with the access token.
    char auth_header[300];
    snprintf(auth_header, sizeof(auth_header), "Bearer %s", g_access_token);
    esp_http_client_set_header(client, "Authorization", auth_header);

    esp_err_t err = esp_http_client_perform(client);
    if (err == ESP_OK) {
        ESP_LOGI(TAG, "GET Status = %d, content_length = %lld",
                 esp_http_client_get_status_code(client),
                 esp_http_client_get_content_length(client));
    } else {
        ESP_LOGE(TAG, "GET request failed: %s", esp_err_to_name(err));
    }
    esp_http_client_cleanup(client);
}

/**
 * @brief Wi-Fi event handler for connection status.
 */
static void event_handler(void* arg, esp_event_base_t event_base, int32_t event_id, void* event_data) {
    if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_STA_START) {
        esp_wifi_connect();
    } else if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_STA_DISCONNECTED) {
        ESP_LOGI(TAG, "Connect to the AP failed, retrying...");
        esp_wifi_connect();
    } else if (event_base == IP_EVENT && event_id == IP_EVENT_STA_GOT_IP) {
        ip_event_got_ip_t* event = (ip_event_got_ip_t*) event_data;
        ESP_LOGI(TAG, "Got IP address:" IPSTR, IP2STR(&event->ip_info.ip));
        // Set the event bit to signal that we are connected.
        xEventGroupSetBits(wifi_event_group, CONNECTED_BIT);
    }
}

/**
 * @brief Initializes Wi-Fi in Station mode.
 */
void wifi_init_sta(void) {
    wifi_event_group = xEventGroupCreate();

    ESP_ERROR_CHECK(esp_event_handler_instance_register(WIFI_EVENT, ESP_EVENT_ANY_ID, &event_handler, NULL, NULL));
    ESP_ERROR_CHECK(esp_event_handler_instance_register(IP_EVENT, IP_EVENT_STA_GOT_IP, &event_handler, NULL, NULL));

    wifi_config_t wifi_config = {
        .sta = {
            .ssid = WIFI_SSID,
            .password = WIFI_PASS,
            .threshold.authmode = WIFI_AUTH_WPA2_PSK,
        },
    };
    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA));
    ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_STA, &wifi_config));
    ESP_ERROR_CHECK(esp_wifi_start());

    ESP_LOGI(TAG, "Wi-Fi initialization finished.");
}

/**
 * @brief Custom function to read a line from the serial input.
 * @param buffer The buffer to store the read line.
 * @param max_len The maximum length of the buffer.
 */
void read_line_from_serial(char *buffer, size_t max_len) {
    int i = 0;
    while (i < max_len - 1) {
        char c;
        if (uart_read_bytes(UART_NUM_0, &c, 1, portMAX_DELAY) > 0) {
            // Echo the character back to the console for user feedback.
            printf("%c", c);
            if (c == '\r' || c == '\n') {
                buffer[i] = '\0';
                printf("\n"); // Print a new line for cleaner output.
                return;
            }
            buffer[i++] = c;
        }
    }
    buffer[i] = '\0'; // Ensure null-termination.
    printf("\nBuffer overflow. Please try again.\n");
}

/**
 * @brief The main task that handles the authentication flow.
 */
void auth_flow_task(void *pvParameters) {
    ESP_LOGI(TAG, "Auth flow task started, waiting for WiFi connection...");
    
    // Wait for the CONNECTED_BIT event to be set, indicating a successful Wi-Fi connection.
    xEventGroupWaitBits(wifi_event_group, CONNECTED_BIT, pdFALSE, pdTRUE, portMAX_DELAY);
    
    ESP_LOGI(TAG, "Wi-Fi connected. Starting auth flow.");
    
    char code_challenge[PKCE_CODE_CHALLENGE_LEN + 1] = {0};
    generate_pkce_codes(code_challenge);

    // Construct and print the authorization URL for the user.
    char auth_url[512];
    snprintf(auth_url, sizeof(auth_url),
             "https://accounts.spotify.com/authorize?response_type=code&client_id=%s&scope=%s&redirect_uri=%s&code_challenge_method=S256&code_challenge=%s",
             SPOTIFY_CLIENT_ID, SPOTIFY_SCOPE, SPOTIFY_REDIRECT_URI, code_challenge);

    printf("Please copy the URL below, paste it into a browser, and log in to Spotify:\n");
    printf("URL: %s\n\n", auth_url);
    printf("After you authorize, copy the 'code' from the URL you are redirected to and paste it here:\n");
    printf("Waiting for your input...\n");
    
    // Read the authorization code from the serial input provided by the user.
    char auth_code[MAX_AUTH_CODE_LEN] = {0};
    read_line_from_serial(auth_code, sizeof(auth_code));
    
    if (strlen(auth_code) > 0) {
        ESP_LOGI(TAG, "Received authorization code: %s", auth_code);
        exchange_code_for_token(auth_code);
    } else {
        ESP_LOGE(TAG, "Failed to read authorization code.");
    }
    
    // Check if tokens were received and print them.
    if (strlen(g_access_token) > 0) {
        ESP_LOGI(TAG, "Authentication successful!");
        ESP_LOGI(TAG, "Access Token: %s", g_access_token);
        ESP_LOGI(TAG, "Refresh Token: %s", g_refresh_token);

        // Now that we have the access token, let's get the currently playing song.
        // We'll run this in a loop to check for updates periodically.
        while (1) {
            get_currently_playing_song();
            vTaskDelay(pdMS_TO_TICKS(10000)); // Wait for 10 seconds before checking again.
        }
    } else {
        ESP_LOGE(TAG, "Authentication failed. Tokens not received.");
    }

    // This is an example of refreshing the token after it expires.
    vTaskDelay(pdMS_TO_TICKS(3600000)); // Wait for 1 hour.
    refresh_access_token();

    vTaskDelete(NULL); // The task has completed its purpose.
}

// Main application entry point.
void app_main(void) {
    // Initialize NVS (Non-Volatile Storage) for Wi-Fi credentials.
    esp_err_t ret = nvs_flash_init();
    if (ret == ESP_ERR_NVS_NO_FREE_PAGES || ret == ESP_ERR_NVS_NOT_INITIALIZED) {
        ESP_ERROR_CHECK(nvs_flash_erase());
        ret = nvs_flash_init();
    }
    ESP_ERROR_CHECK(ret);

    // Initialize TCP/IP stack.
    ESP_ERROR_CHECK(esp_netif_init());
    ESP_ERROR_CHECK(esp_event_loop_create_default());

    // Configure and install UART driver for serial communication.
    const uart_config_t uart_config = {
        .baud_rate = 115200,
        .data_bits = UART_DATA_8_BITS,
        .parity = UART_PARITY_DISABLE,
        .stop_bits = UART_STOP_BITS_1,
        .flow_ctrl = UART_HW_FLOWCTRL_DISABLE,
        .source_clk = UART_SCLK_DEFAULT,
    };
    ESP_ERROR_CHECK(uart_driver_install(UART_NUM_0, 256, 0, 0, NULL, 0));
    ESP_ERROR_CHECK(uart_param_config(UART_NUM_0, &uart_config));
    ESP_ERROR_CHECK(uart_set_pin(UART_NUM_0, UART_PIN_NO_CHANGE, UART_PIN_NO_CHANGE, UART_PIN_NO_CHANGE, UART_PIN_NO_CHANGE));

    // Initialize Wi-Fi.
    esp_netif_create_default_wifi_sta();
    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_wifi_init(&cfg));

    // Start the Wi-Fi connection process.
    wifi_init_sta();

    // Create the main authentication task.
    xTaskCreate(&auth_flow_task, "auth_flow_task", 8192, NULL, 5, NULL);
}
