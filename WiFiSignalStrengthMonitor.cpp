#include <cstdio>
#include <thread>
#include <chrono>
#include <atomic>
#include <stdlib.h>
#include "NetworkManagerLogger.h"
#include "NetworkManagerImplementation.h"
#include "WiFiSignalStrengthMonitor.h"

#define BUFFER_SIZE 512
#define rssid_command "wpa_cli signal_poll"
#define ssid_command "wpa_cli status"

namespace WPEFramework
{
    namespace Plugin
    {
        static const float signalStrengthThresholdExcellent = -50.0f;
        static const float signalStrengthThresholdGood = -60.0f;
        static const float signalStrengthThresholdFair = -67.0f;
        extern NetworkManagerImplementation* _instance;

        std::string WiFiSignalStrengthMonitor::retrieveValues(const char *command, const char* keyword, char *output_buffer, size_t output_buffer_size)
        {
            std::string key, value;
            std::string keystr = "";

            FILE *fp = popen(command, "r");
            if (!fp)
            {
                NMLOG_ERROR("Failed in getting output from command %s",command);
                return keystr;
            }

            while ((!feof(fp)) && (fgets(output_buffer, output_buffer_size, fp) != NULL))
            {
                std::istringstream mystream(output_buffer);
                if(std::getline(std::getline(mystream, key, '=') >> std::ws, value))
                    if (key == keyword) {
                        keystr = value;
                        break;
                    }
            }
            pclose(fp);

            return keystr;
        }

        void WiFiSignalStrengthMonitor::getSignalData(std::string &ssid, Exchange::INetworkManager::WiFiSignalQuality &quality, std::string &strengthOut)
        {
            float signalStrengthOut = 0.0f;
            char buff[BUFFER_SIZE] = {'\0'};

            ssid = retrieveValues(ssid_command, "ssid", buff, sizeof (buff));
            if (ssid.empty())
            {
                quality = Exchange::INetworkManager::WIFI_SIGNAL_DISCONNECTED;
                strengthOut = "0.00";
                return;
            }

            string signalStrength = retrieveValues(rssid_command, "RSSI", buff, sizeof (buff));
            if (!signalStrength.empty()) {
                signalStrengthOut = std::stof(signalStrength.c_str());
                strengthOut = signalStrength;
            }
            else
                NMLOG_ERROR("signalStrength is empty");

            NMLOG_DEBUG("SSID = %s Signal Strength %f db", ssid.c_str(), signalStrengthOut);
            if (signalStrengthOut == 0.0f)
            {
                quality = Exchange::INetworkManager::WIFI_SIGNAL_DISCONNECTED;
                strengthOut = "0.00";
            }
            else if (signalStrengthOut >= signalStrengthThresholdExcellent && signalStrengthOut < 0)
            {
                quality = Exchange::INetworkManager::WIFI_SIGNAL_EXCELLENT;
            }
            else if (signalStrengthOut >= signalStrengthThresholdGood && signalStrengthOut < signalStrengthThresholdExcellent)
            {
                quality = Exchange::INetworkManager::WIFI_SIGNAL_GOOD;
            }
            else if (signalStrengthOut >= signalStrengthThresholdFair && signalStrengthOut < signalStrengthThresholdGood)
            {
                quality = Exchange::INetworkManager::WIFI_SIGNAL_FAIR;
            }
            else
            {
                quality = Exchange::INetworkManager::WIFI_SIGNAL_WEAK;
            };
        }

        void WiFiSignalStrengthMonitor::startWiFiSignalStrengthMonitor(int interval)
        {
            stopThread = false;
            if (isRunning) {
                NMLOG_INFO("WiFiSignalStrengthMonitor Thread is already running.");
                return;
            }
            isRunning = true;
            monitorThread = std::thread(&WiFiSignalStrengthMonitor::monitorThreadFunction, this, interval);
            monitorThread.detach();
        }

        void WiFiSignalStrengthMonitor::monitorThreadFunction(int interval)
        {
            static Exchange::INetworkManager::WiFiSignalQuality oldSignalQuality = Exchange::INetworkManager::WIFI_SIGNAL_DISCONNECTED;
            NMLOG_INFO("WiFiSignalStrengthMonitor thread started ! (%d)", interval);
            while (!stopThread)
            {
                string ssid = "";
                string signalStrength;
                Exchange::INetworkManager::WiFiSignalQuality newSignalQuality;
                if (_instance != nullptr)
                {
                    NMLOG_DEBUG("checking WiFi signal strength");
                    getSignalData(ssid, newSignalQuality, signalStrength);
                    if(oldSignalQuality != newSignalQuality)
                    {
                        NMLOG_INFO("Notifying WiFiSignalStrengthChangedEvent %s", signalStrength.c_str());
                        oldSignalQuality = newSignalQuality;
                        _instance->ReportWiFiSignalStrengthChange(ssid, signalStrength, newSignalQuality);
                    }

                    if(newSignalQuality == Exchange::INetworkManager::WIFI_SIGNAL_DISCONNECTED)
                    {
                        NMLOG_WARNING("WiFiSignalStrengthChanged to disconnect - WiFiSignalStrengthMonitor exiting");
                        stopThread= false;
                        break; // Let the thread exit naturally
                    }
                }
                else
                    NMLOG_FATAL("NetworkManagerImplementation pointer error !");
                // Wait for the specified interval or until notified to stop
                std::this_thread::sleep_for(std::chrono::seconds(interval));
            }
            isRunning = false;
        }
    }
}
