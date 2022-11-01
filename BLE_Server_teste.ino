//Detector de BLE
// -- Bibliotecas
#include <BLEDevice.h>
#include <BLEServer.h>
#include <BLEUtils.h>
#include <BLEScan.h>
#include <BLEAdvertisedDevice.h>

// -- Variáveis
BLEServer* pServer = NULL;
BLECharacteristic* pCharacteristic = NULL;
#define SERVICE_UUID        "4fafc201-1fb5-459e-8fcc-c5c9c331914b"
#define CHARACTERISTIC_UUID "beb5483e-36e1-4688-b7f5-ea07361b26a8"
#define PASSKEY 999999
int RSSI_THRESHOLD = -80;

// -- Objetos
BLEAdvertisedDevice advertisedDevice;
SemaphoreHandle_t xGuiSemaphore;

typedef struct{
  String addr;
  int rssi;
}auth_devices;

auth_devices dispositivos_autenticados[50];
int index_ad = 0;

// -- Handler
static void my_gap_event_handler(esp_gap_ble_cb_event_t event, esp_ble_gap_cb_param_t* param) {
  if (event == ESP_GAP_BLE_READ_RSSI_COMPLETE_EVT){
    //Serial.print("RSSI status: ");Serial.println(param->read_rssi_cmpl.status);
    Serial.print("RSSI: ");Serial.println(param->read_rssi_cmpl.rssi);
    Serial.print("Address: ");Serial.println(BLEAddress(param->read_rssi_cmpl.remote_addr).toString().c_str());

    // Atualiza RSSI
    dispositivos_autenticados[index_ad%50].addr = BLEAddress(param->read_rssi_cmpl.remote_addr).toString().c_str();
    dispositivos_autenticados[index_ad%50].rssi = param->read_rssi_cmpl.rssi;
    index_ad++;
  }  
}

// - Setup
void setup() {
  Serial.begin(115200);
  pinMode(LED_BUILTIN, OUTPUT);
  bleInit();
  xGuiSemaphore = xSemaphoreCreateMutex();
  BLEDevice::setCustomGapHandler(my_gap_event_handler);
  xTaskCreate(ble_task, "ble_task", 2048, NULL, 1, NULL); 
}

// -- Loop
void loop() {

  
  
}

/////////////////////
//BLE Secure Server//
/////////////////////

class ServerCallback: public BLEServerCallbacks {
    void onConnect(BLEServer* pServer) {
      Serial.println(" - ServerCallback - onConnect");
    };

    void onDisconnect(BLEServer* pServer) {
      Serial.println(" - ServerCallback - onDisconnect");
    }
};

class SecurityCallback : public BLESecurityCallbacks {

  uint32_t onPassKeyRequest(){
    return 000000;
  }

  void onPassKeyNotify(uint32_t pass_key){}

  bool onConfirmPIN(uint32_t pass_key){
    vTaskDelay(5000);
    return true;
  }

  bool onSecurityRequest(){
    return true;
  }

  void onAuthenticationComplete(esp_ble_auth_cmpl_t cmpl){
    if(cmpl.success){
      Serial.println("   - SecurityCallback - Authentication Success");   
//      Serial.printf("Advertised Device: %s \n", advertisedDevice.toString().c_str()); 
//      Serial.print("RSSI: ");
//      Serial.println(advertisedDevice.getRSSI());
//      Serial.print("Address: ");
//      Serial.println(advertisedDevice.getAddress().toString().c_str());
      
      // Solicita leitura de RSSI do disposito remoto (retorna no ESP_GAP_BLE_READ_RSSI_COMPLETE_EVT)
      esp_err_t ret = esp_ble_gap_read_rssi(cmpl.bd_addr);
//      Serial.println(ret);
    }else{
      Serial.println("   - SecurityCallback - Authentication Failure*");
      pServer->removePeerDevice(pServer->getConnId(), true);
    }
    BLEDevice::startAdvertising();
  }
};

void bleSecurity(){
  esp_ble_auth_req_t auth_req = ESP_LE_AUTH_REQ_SC_MITM_BOND;
  esp_ble_io_cap_t iocap = ESP_IO_CAP_OUT;          
  uint8_t key_size = 16;     
  uint8_t init_key = ESP_BLE_ENC_KEY_MASK | ESP_BLE_ID_KEY_MASK;
  uint8_t rsp_key = ESP_BLE_ENC_KEY_MASK | ESP_BLE_ID_KEY_MASK;
  uint32_t passkey = PASSKEY;
  uint8_t auth_option = ESP_BLE_ONLY_ACCEPT_SPECIFIED_AUTH_DISABLE;
  esp_ble_gap_set_security_param(ESP_BLE_SM_SET_STATIC_PASSKEY, &passkey, sizeof(uint32_t));
  esp_ble_gap_set_security_param(ESP_BLE_SM_AUTHEN_REQ_MODE, &auth_req, sizeof(uint8_t));
  esp_ble_gap_set_security_param(ESP_BLE_SM_IOCAP_MODE, &iocap, sizeof(uint8_t));
  esp_ble_gap_set_security_param(ESP_BLE_SM_MAX_KEY_SIZE, &key_size, sizeof(uint8_t));
  esp_ble_gap_set_security_param(ESP_BLE_SM_ONLY_ACCEPT_SPECIFIED_SEC_AUTH, &auth_option, sizeof(uint8_t));
  esp_ble_gap_set_security_param(ESP_BLE_SM_SET_INIT_KEY, &init_key, sizeof(uint8_t));
  esp_ble_gap_set_security_param(ESP_BLE_SM_SET_RSP_KEY, &rsp_key, sizeof(uint8_t));
}

void bleInit(){
  BLEDevice::init("BLE-Secure-Server");
  BLEDevice::setEncryptionLevel(ESP_BLE_SEC_ENCRYPT);
  BLEDevice::setSecurityCallbacks(new SecurityCallback());

  pServer = BLEDevice::createServer();
  pServer->setCallbacks(new ServerCallback());

  BLEService *pService = pServer->createService(SERVICE_UUID);
  pCharacteristic = pService->createCharacteristic(
                      CHARACTERISTIC_UUID,
                      BLECharacteristic::PROPERTY_READ   |
                      BLECharacteristic::PROPERTY_WRITE  |
                      BLECharacteristic::PROPERTY_NOTIFY 
                    );

  pCharacteristic->setAccessPermissions(ESP_GATT_PERM_READ_ENCRYPTED | ESP_GATT_PERM_WRITE_ENCRYPTED);
  pService->start();

  BLEAdvertising *pAdvertising = BLEDevice::getAdvertising();
  pAdvertising->addServiceUUID(SERVICE_UUID);
  pAdvertising->setScanResponse(false);
  pAdvertising->setMinPreferred(0x0);
  BLEDevice::startAdvertising();

  bleSecurity();
}

static void ble_task(void *arg){
  
  uint32_t value = 0;

  while(1){
    
      xSemaphoreTake(xGuiSemaphore, portMAX_DELAY);
      int connectedCount = pServer->getConnectedCount();
       Serial.printf("connectedCount: %d\n", connectedCount);
  
      if (connectedCount >0) { 
          pCharacteristic->setValue((uint8_t*)&value, 4);
          pCharacteristic->notify();   
          
      }
      value++;
      
      xSemaphoreGive(xGuiSemaphore);
      vTaskDelay(pdMS_TO_TICKS(1000));     
  }
}
