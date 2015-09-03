//*****************************************************************************
//
//  Copyright (C) 2014 Texas Instruments Incorporated - http://www.ti.com/ 
// 
// 
//  Redistribution and use in source and binary forms, with or without 
//  modification, are permitted provided that the following conditions 
//  are met:
//
//  Redistributions of source code must retain the above copyright 
//  notice, this list of conditions and the following disclaimer.
//
//  Redistributions in binary form must reproduce the above copyright
//  notice, this list of conditions and the following disclaimer in the 
//  documentation and/or other materials provided with the   
//  distribution.
//
//  Neither the name of Texas Instruments Incorporated nor the names of
//  its contributors may be used to endorse or promote products derived
//  from this software without specific prior written permission.
//
//  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS 
//  "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT 
//  LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
//  A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT 
//  OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, 
//  SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT 
//  LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
//  DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
//  THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT 
//  (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE 
//  OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
//
//*****************************************************************************


//*****************************************************************************
//
// Application Name     -   Getting started with WLAN STATION
// Application Overview -   This is a sample application demonstrating how to
//                          start CC3200 in WLAN-Station mode and connect to a
//                          Wi-Fi access-point. The application connects to an
//                          access-point and ping the gateway. It also checks
//                          for an internet connectivity by pinging "www.ti.com"
// Application Details  -
// http://processors.wiki.ti.com/index.php/CC32xx_Getting_Started_with_WLAN_Station
// or
// doc\examples\CC32xx_Getting_Started_with_WLAN_Station.pdf
//
//*****************************************************************************


//****************************************************************************
//
//! \addtogroup getting_started_sta
//! @{
//
//****************************************************************************

// Standard includes
#include <stdlib.h>
#include <string.h>

// Simplelink includes
#include "simplelink.h"
#include "wlan.h"

//Driverlib includes
#include "hw_types.h"
#include "hw_ints.h"
#include "rom.h"
#include "rom_map.h"
#include "interrupt.h"
#include "prcm.h"
#include "utils.h"

//Free_rtos/ti-rtos includes
#include "osi.h"

//Common interface includes
#include "gpio_if.h"
#ifndef NOTERM
#include "uart_if.h"
#endif
#include "common.h"
#include "pinmux.h"

#include "netcfg.h"

//*****************************************************************************
//                 DEFINE
//*****************************************************************************

#define APPLICATION_NAME        "AccessPoints Scan & reposit at Server"
#define APPLICATION_VERSION     "1.1.0"

#define WLAN_CONNECT_COUNT  10
#define WLAN_SCAN_COUNT     20

#define OSI_STACK_SIZE      2048
#define BUF_SIZE            1400
#define TCP_PACKET_COUNT    1000

#define IP_ADDR             ((192<<24) | (168<<16) | (20<<8) | (101))
#define PORT_NUM            1011
#define TESTAP_SID_PREFIX   "NIPA_"
#define TESTAP_SCAN_COUNT   3

//*****************************************************************************
//                Declaire Data type
//*****************************************************************************

// Application specific status/error codes
typedef enum{
    // Choosing -0x7D0 to avoid overlap w/ host-driver's error codes
    TCP_CLIENT_FAILED = -0x7D0,
    TCP_SERVER_FAILED = TCP_CLIENT_FAILED - 1,
    DEVICE_NOT_IN_STATION_MODE = TCP_SERVER_FAILED - 1,

    STATUS_CODE_MAX = -0xBB8
}e_AppStatusCodes;


//*****************************************************************************
//                 GLOBAL VARIABLES -- Start
//*****************************************************************************
unsigned long  g_ulStatus = 0;//SimpleLink Status
unsigned char  g_ucConnectionSSID[SSID_LEN_MAX+1]; //Connection SSID
unsigned char  g_ucConnectionBSSID[BSSID_LEN_MAX]; //Connection BSSID
unsigned long  g_ulDestinationIp = IP_ADDR;
unsigned int   g_uiPortNum = PORT_NUM;
unsigned char  g_ucConnectionStatus = 0;
unsigned char  g_ucSimplelinkstarted = 0;
unsigned long  g_ulIpAddr = 0;
/* 20150903_CIB */
Sl_WlanNetworkEntry_t netEntries[100];
Sl_WlanNetworkEntry_t testAP[20];
/* OLD */
//Sl_WlanNetworkEntry_t netEntries[20];
//Sl_WlanNetworkEntry_t testAP[5];

int scanCount;
static char ConSid[MAXIMAL_SSID_LENGTH];
static int ConRssi;
unsigned long curtick=0;
int socketID;
            
unsigned long   g_ulGatewayIP = 0;
char tcpSendBuf[BUF_SIZE];
char tcpRcvBuf[BUF_SIZE];
char cmdBuf[512];

#if defined(ccs) || defined (gcc)
extern void (* const g_pfnVectors[])(void);
#endif
#if defined(ewarm)
extern uVectorEntry __vector_table;
#endif
//*****************************************************************************
//                 GLOBAL VARIABLES -- End
//*****************************************************************************



//****************************************************************************
//                      LOCAL FUNCTION PROTOTYPES
//****************************************************************************
static long WlanConnect();
void WlanStationMode( void *pvParameters );
static long CheckLanConnection();
static long CheckInternetConnection();
static void InitializeAppVariables();
static long ConfigureSimpleLinkToDefaultState();


#ifdef USE_FREERTOS
//*****************************************************************************
// FreeRTOS User Hook Functions enabled in FreeRTOSConfig.h
//*****************************************************************************

//*****************************************************************************
//
//! \brief Application defined hook (or callback) function - assert
//!
//! \param[in]  pcFile - Pointer to the File Name
//! \param[in]  ulLine - Line Number
//! 
//! \return none
//!
//*****************************************************************************
void
vAssertCalled( const char *pcFile, unsigned long ulLine )
{
    //Handle Assert here
    while(1)
    {
    }
}

//*****************************************************************************
//
//! \brief Application defined idle task hook
//! 
//! \param  none
//! 
//! \return none
//!
//*****************************************************************************
void
vApplicationIdleHook( void)
{
    //Handle Idle Hook for Profiling, Power Management etc
}

//*****************************************************************************
//
//! \brief Application defined malloc failed hook
//! 
//! \param  none
//! 
//! \return none
//!
//*****************************************************************************
void vApplicationMallocFailedHook()
{
    //Handle Memory Allocation Errors
    while(1)
    {
    }
}

//*****************************************************************************
//
//! \brief Application defined stack overflow hook
//! 
//! \param  none
//! 
//! \return none
//!
//*****************************************************************************
void vApplicationStackOverflowHook( OsiTaskHandle *pxTask,
                                   signed char *pcTaskName)
{
    //Handle FreeRTOS Stack Overflow
    while(1)
    {
    }
}
#endif //USE_FREERTOS


//*****************************************************************************
// SimpleLink Asynchronous Event Handlers -- Start
//*****************************************************************************


//*****************************************************************************
//
//! \brief The Function Handles WLAN Events
//!
//! \param[in]  pWlanEvent - Pointer to WLAN Event Info
//!
//! \return None
//!
//*****************************************************************************
void SimpleLinkWlanEventHandler(SlWlanEvent_t *pWlanEvent)
{
    if(!pWlanEvent)
    {
        return;
    }

    switch(pWlanEvent->Event)
    {
        case SL_WLAN_CONNECT_EVENT:
        {
            SET_STATUS_BIT(g_ulStatus, STATUS_BIT_CONNECTION);
            
            //
            // Information about the connected AP (like name, MAC etc) will be
            // available in 'slWlanConnectAsyncResponse_t'-Applications
            // can use it if required
            //
            //  slWlanConnectAsyncResponse_t *pEventData = NULL;
            // pEventData = &pWlanEvent->EventData.STAandP2PModeWlanConnected;
            //
            
            // Copy new connection SSID and BSSID to global parameters
            memcpy(g_ucConnectionSSID,pWlanEvent->EventData.
                   STAandP2PModeWlanConnected.ssid_name,
                   pWlanEvent->EventData.STAandP2PModeWlanConnected.ssid_len);
            memcpy(g_ucConnectionBSSID,
                   pWlanEvent->EventData.STAandP2PModeWlanConnected.bssid,
                   SL_BSSID_LENGTH);

            UART_PRINT("[WLAN EVENT] STA Connected to the AP: %s ,"
                        "BSSID: %x:%x:%x:%x:%x:%x\n\r",
                      g_ucConnectionSSID,g_ucConnectionBSSID[0],
                      g_ucConnectionBSSID[1],g_ucConnectionBSSID[2],
                      g_ucConnectionBSSID[3],g_ucConnectionBSSID[4],
                      g_ucConnectionBSSID[5]);
        }
        break;

        case SL_WLAN_DISCONNECT_EVENT:
        {
            slWlanConnectAsyncResponse_t*  pEventData = NULL;

            CLR_STATUS_BIT(g_ulStatus, STATUS_BIT_CONNECTION);
            CLR_STATUS_BIT(g_ulStatus, STATUS_BIT_IP_AQUIRED);

            pEventData = &pWlanEvent->EventData.STAandP2PModeDisconnected;

            // If the user has initiated 'Disconnect' request, 
            //'reason_code' is SL_USER_INITIATED_DISCONNECTION 
            if(SL_USER_INITIATED_DISCONNECTION == pEventData->reason_code)
            {
                UART_PRINT("[WLAN EVENT]Device disconnected from the AP: %s,"
                "BSSID: %x:%x:%x:%x:%x:%x on application's request \n\r",
                           g_ucConnectionSSID,g_ucConnectionBSSID[0],
                           g_ucConnectionBSSID[1],g_ucConnectionBSSID[2],
                           g_ucConnectionBSSID[3],g_ucConnectionBSSID[4],
                           g_ucConnectionBSSID[5]);
            }
            else
            {
                UART_PRINT("[WLAN ERROR]Device disconnected from the AP AP: %s,"
                "BSSID: %x:%x:%x:%x:%x:%x on an ERROR..!! \n\r",
                           g_ucConnectionSSID,g_ucConnectionBSSID[0],
                           g_ucConnectionBSSID[1],g_ucConnectionBSSID[2],
                           g_ucConnectionBSSID[3],g_ucConnectionBSSID[4],
                           g_ucConnectionBSSID[5]);
            }
            memset(g_ucConnectionSSID,0,sizeof(g_ucConnectionSSID));
            memset(g_ucConnectionBSSID,0,sizeof(g_ucConnectionBSSID));
        }
        break;

        default:
        {
            UART_PRINT("[WLAN EVENT] Unexpected event [0x%x]\n\r",
                       pWlanEvent->Event);
        }
        break;
    }
}

//*****************************************************************************
//
//! \brief This function handles network events such as IP acquisition, IP
//!           leased, IP released etc.
//!
//! \param[in]  pNetAppEvent - Pointer to NetApp Event Info 
//!
//! \return None
//!
//*****************************************************************************
void SimpleLinkNetAppEventHandler(SlNetAppEvent_t *pNetAppEvent)
{
    if(!pNetAppEvent)
    {
        return;
    }

    switch(pNetAppEvent->Event)
    {
        case SL_NETAPP_IPV4_IPACQUIRED_EVENT:
        {
            SlIpV4AcquiredAsync_t *pEventData = NULL;

            SET_STATUS_BIT(g_ulStatus, STATUS_BIT_IP_AQUIRED);
            
            //Ip Acquired Event Data
            pEventData = &pNetAppEvent->EventData.ipAcquiredV4;
            g_ulIpAddr = pEventData->ip;
            
            //Gateway IP address
            g_ulGatewayIP = pEventData->gateway;
            
            UART_PRINT("[NETAPP EVENT] IP Acquired: IP=%d.%d.%d.%d , "
            "Gateway=%d.%d.%d.%d\n\r", 
                            SL_IPV4_BYTE(g_ulIpAddr,3),
                            SL_IPV4_BYTE(g_ulIpAddr,2),
                            SL_IPV4_BYTE(g_ulIpAddr,1),
                            SL_IPV4_BYTE(g_ulIpAddr,0),
                            SL_IPV4_BYTE(g_ulGatewayIP,3),
                            SL_IPV4_BYTE(g_ulGatewayIP,2),
                            SL_IPV4_BYTE(g_ulGatewayIP,1),
                            SL_IPV4_BYTE(g_ulGatewayIP,0));
        }
        break;

        default:
        {
            UART_PRINT("[NETAPP EVENT] Unexpected event [0x%x] \n\r",
                       pNetAppEvent->Event);
        }
        break;
    }
}


//*****************************************************************************
//
//! \brief This function handles HTTP server events
//!
//! \param[in]  pServerEvent - Contains the relevant event information
//! \param[in]    pServerResponse - Should be filled by the user with the
//!                                      relevant response information
//!
//! \return None
//!
//****************************************************************************
void SimpleLinkHttpServerCallback(SlHttpServerEvent_t *pHttpEvent,
                                  SlHttpServerResponse_t *pHttpResponse)
{
    // Unused in this application
}

//*****************************************************************************
//
//! \brief This function handles General Events
//!
//! \param[in]     pDevEvent - Pointer to General Event Info 
//!
//! \return None
//!
//*****************************************************************************
void SimpleLinkGeneralEventHandler(SlDeviceEvent_t *pDevEvent)
{
    if(!pDevEvent)
    {
        return;
    }

    //
    // Most of the general errors are not FATAL are are to be handled
    // appropriately by the application
    //
    UART_PRINT("[GENERAL EVENT] - ID=[%d] Sender=[%d]\n\n",
               pDevEvent->EventData.deviceEvent.status, 
               pDevEvent->EventData.deviceEvent.sender);
}


//*****************************************************************************
//
//! This function handles socket events indication
//!
//! \param[in]      pSock - Pointer to Socket Event Info
//!
//! \return None
//!
//*****************************************************************************
void SimpleLinkSockEventHandler(SlSockEvent_t *pSock)
{
    if(!pSock)
    {
        return;
    }

    //
    // This application doesn't work w/ socket - Events are not expected
    //
    switch( pSock->Event )
    {
        case SL_SOCKET_TX_FAILED_EVENT:
            switch( pSock->EventData.status )
            {
                case SL_ECLOSE: 
                    UART_PRINT("[SOCK ERROR] - close socket (%d) operation "
                    "failed to transmit all queued packets\n\n", 
                           pSock->EventData.sd);
                    break;
                default: 
                    UART_PRINT("[SOCK ERROR] - TX FAILED : socket %d , reason"
                        "(%d) \n\n",
                           pSock->EventData.sd, pSock->EventData.status);
            }
            break;

        default:
            UART_PRINT("[SOCK EVENT] - Unexpected Event [%x0x]\n\n",pSock->Event);
    }
}


//*****************************************************************************
// SimpleLink Asynchronous Event Handlers -- End
//*****************************************************************************

static unsigned long sysCurrentTime(void)
{
   return xTaskGetTickCount();

}

static void doInputConfiguration(void)
{
    int rSize;
    UART_PRINT("-------------------------------------------------------------------------------------\n");
    UART_PRINT(" AP which  has strongest signal among Public Access Points should be connected.\n");
    UART_PRINT(" if there is no Public APs, Connect AP('%s') with Key('%s')\n",SSID_NAME,SECURITY_KEY);
    UART_PRINT(" if you want to change this conf, Enter( 'y') else Enter Any key \n");
    UART_PRINT("-------------------------------------------------------------------------------------\n");
    //rSize = GetCmd(cmdBuf, 512);
}

static int doGatherTestAP(void)
{
    int i;
    int testap_cnt=0;
    for(i=0; i<scanCount;i++)
    {
        if( strncmp(netEntries[i].ssid,TESTAP_SID_PREFIX,strlen(TESTAP_SID_PREFIX)) == 0){
        	//UART_PRINT("search ok[%d] , count=%d", i, scanCount);
            memcpy(&testAP[testap_cnt ++], &netEntries[i], sizeof(Sl_WlanNetworkEntry_t));
        }
    }
    return (testap_cnt >= TESTAP_SCAN_COUNT) ? SUCCESS : FAILURE;
}

//*****************************************************************************
//
//! This function initializes the application variables
//!
//! \param[in]    None
//!
//! \return None
//!
//*****************************************************************************
static void InitializeAppVariables()
{
    g_ulStatus = 0;
    g_ulGatewayIP = 0;
    memset(g_ucConnectionSSID,0,sizeof(g_ucConnectionSSID));
    memset(g_ucConnectionBSSID,0,sizeof(g_ucConnectionBSSID));
    g_ulDestinationIp = IP_ADDR;
    g_uiPortNum = PORT_NUM;
    ConRssi = -100;
}


static void InitializeConnectAP()
{
    ConSid[0] = 0;
    ConRssi =0;
}

static char *GetConnectedSid()
{
    return &ConSid[0];
}

//*****************************************************************************
//! \brief This function puts the device in its default state. It:
//!           - Set the mode to STATION
//!           - Configures connection policy to Auto and AutoSmartConfig
//!           - Deletes all the stored profiles
//!           - Enables DHCP
//!           - Disables Scan policy
//!           - Sets Tx power to maximum
//!           - Sets power policy to normal
//!           - Unregister mDNS services
//!           - Remove all filters
//!
//! \param   none
//! \return  On success, zero is returned. On error, negative is returned
//*****************************************************************************

static long ConfigureSimpleLinkToDefaultState()
{
    SlVersionFull   ver = {0};
    _WlanRxFilterOperationCommandBuff_t  RxFilterIdMask = {0};

    unsigned char ucVal = 1;
    unsigned char ucConfigOpt = 0;
    unsigned char ucConfigLen = 0;
    unsigned char ucPower = 0;

    long lRetVal = -1;
    long lMode = -1;

    lMode = sl_Start(0, 0, 0);
    ASSERT_ON_ERROR(lMode);
    GPIO_IF_LedOn(MCU_RED_LED_GPIO);

    // If the device is not in station-mode, try configuring it in station-mode 
    if (ROLE_STA != lMode)
    {
        if (ROLE_AP == lMode)
        {
            // If the device is in AP mode, we need to wait for this event 
            // before doing anything 
            while(!IS_IP_ACQUIRED(g_ulStatus))
            {
#ifndef SL_PLATFORM_MULTI_THREADED
              _SlNonOsMainLoopTask(); 
#endif
            }
        }

        // Switch to STA role and restart 
        lRetVal = sl_WlanSetMode(ROLE_STA);
        ASSERT_ON_ERROR(lRetVal);

        lRetVal = sl_Stop(0xFF);
        ASSERT_ON_ERROR(lRetVal);

        lRetVal = sl_Start(0, 0, 0);
        ASSERT_ON_ERROR(lRetVal);

        // Check if the device is in station again 
        if (ROLE_STA != lRetVal)
        {
            // We don't want to proceed if the device is not coming up in STA-mode 
            return DEVICE_NOT_IN_STATION_MODE;
        }
    }
    
    // Get the device's version-information
    ucConfigOpt = SL_DEVICE_GENERAL_VERSION;
    ucConfigLen = sizeof(ver);
    lRetVal = sl_DevGet(SL_DEVICE_GENERAL_CONFIGURATION, &ucConfigOpt, 
                                &ucConfigLen, (unsigned char *)(&ver));
    ASSERT_ON_ERROR(lRetVal);
    
    UART_PRINT("Host Driver Version: %s\n\r",SL_DRIVER_VERSION);
    UART_PRINT("Build Version %d.%d.%d.%d.31.%d.%d.%d.%d.%d.%d.%d.%d\n\r",
    ver.NwpVersion[0],ver.NwpVersion[1],ver.NwpVersion[2],ver.NwpVersion[3],
    ver.ChipFwAndPhyVersion.FwVersion[0],ver.ChipFwAndPhyVersion.FwVersion[1],
    ver.ChipFwAndPhyVersion.FwVersion[2],ver.ChipFwAndPhyVersion.FwVersion[3],
    ver.ChipFwAndPhyVersion.PhyVersion[0],ver.ChipFwAndPhyVersion.PhyVersion[1],
    ver.ChipFwAndPhyVersion.PhyVersion[2],ver.ChipFwAndPhyVersion.PhyVersion[3]);

    // Set connection policy to Auto + SmartConfig 
    //      (Device's default connection policy)
    lRetVal = sl_WlanPolicySet(SL_POLICY_CONNECTION, 
                                SL_CONNECTION_POLICY(1, 0, 0, 0, 1), NULL, 0);
    ASSERT_ON_ERROR(lRetVal);

    // Remove all profiles
    lRetVal = sl_WlanProfileDel(0xFF);
    ASSERT_ON_ERROR(lRetVal);

    

    //
    // Device in station-mode. Disconnect previous connection if any
    // The function returns 0 if 'Disconnected done', negative number if already
    // disconnected Wait for 'disconnection' event if 0 is returned, Ignore 
    // other return-codes
    //
    lRetVal = sl_WlanDisconnect();
    if(0 == lRetVal)
    {
        // Wait
        while(IS_CONNECTED(g_ulStatus))
        {
#ifndef SL_PLATFORM_MULTI_THREADED
              _SlNonOsMainLoopTask(); 
#endif
        }
    }

    // Enable DHCP client
    lRetVal = sl_NetCfgSet(SL_IPV4_STA_P2P_CL_DHCP_ENABLE,1,1,&ucVal);
    ASSERT_ON_ERROR(lRetVal);

    // Disable scan
    ucConfigOpt = SL_SCAN_POLICY(0);
    lRetVal = sl_WlanPolicySet(SL_POLICY_SCAN , ucConfigOpt, NULL, 0);
    ASSERT_ON_ERROR(lRetVal);

    // Set Tx power level for station mode
    // Number between 0-15, as dB offset from max power - 0 will set max power
    ucPower = 0;
    lRetVal = sl_WlanSet(SL_WLAN_CFG_GENERAL_PARAM_ID, 
            WLAN_GENERAL_PARAM_OPT_STA_TX_POWER, 1, (unsigned char *)&ucPower);
    ASSERT_ON_ERROR(lRetVal);

    // Set PM policy to normal
    lRetVal = sl_WlanPolicySet(SL_POLICY_PM , SL_NORMAL_POLICY, NULL, 0);
    ASSERT_ON_ERROR(lRetVal);

    // Unregister mDNS services
    lRetVal = sl_NetAppMDNSUnRegisterService(0, 0);
    ASSERT_ON_ERROR(lRetVal);

    // Remove  all 64 filters (8*8)
    memset(RxFilterIdMask.FilterIdMask, 0xFF, 8);
    lRetVal = sl_WlanRxFilterSet(SL_REMOVE_RX_FILTER, (_u8 *)&RxFilterIdMask,
                       sizeof(_WlanRxFilterOperationCommandBuff_t));
    ASSERT_ON_ERROR(lRetVal);

    lRetVal = sl_Stop(SL_STOP_TIMEOUT);
    ASSERT_ON_ERROR(lRetVal);

    InitializeAppVariables();
    
    return lRetVal; // Success
}

/**
  *  \brief TCP Server에게 Data 를 전송한다.
  * @param [in] iSockID     connect 된 Socket의 식별자
  * @param [in] buf           전송할 메시지의 버퍼
  * @param [in] size          메시지의 size 
  * @return  SUCCESS - 성공,  
                 음수 - 실패 에러 코드
  **/
 
static int sendTcpMessage(int iSockID, char *buf, int size)
{
    int iStatus;
    // sending packet
    iStatus = sl_Send(iSockID, buf, size, 0 );
    if( iStatus <= 0 )
    {
        // error
        ASSERT_ON_ERROR(sl_Close(iSockID));
        ASSERT_ON_ERROR(TCP_CLIENT_FAILED);
       
    }
    return SUCCESS;

}

/**
  *  \brief TCP Server로부터 Data 를 수신한다.
  * @param [in] iSockID     connect 된 Socket의 식별자
  * @param [out] buf           수신할 메시지의 버퍼
  * @param [in] size          수신 버퍼의 size 
  * @return  SUCCESS - 성공,  
                 음수 - 실패 에러 코드
  **/
 
static int rcvTcpMessage(int iSockID, char *buf, int size)
{
    int iStatus;
    // sending packet
    iStatus = sl_Recv(iSockID, buf, size, 0 );
    if( iStatus <= 0 )
    {
        // error
		UART_PRINT("receive error");
        ASSERT_ON_ERROR(sl_Close(iSockID));
        ASSERT_ON_ERROR(TCP_CLIENT_FAILED);
    }
    return SUCCESS;

}


/**
  *  \brief TCP 서버를 접속한다.
  * @param [in] addr         tcp 서버의 주소, 4byte 
  * @param [in] usPort      tcp 서버의 접속 Port 번호
  * @param [out] sock      접속 성공시 socket의 식별자 값
  * @return  SUCCESS - 성공,  
                 음수 - 실패 에러 코드
  **/
 
int tcpClientConnect(unsigned long addr, unsigned short usPort, int *sock)
{
    int             iCounter;
    SlSockAddrIn_t  sAddr;
    int             iAddrSize;
    int             iSockID;
    int             iStatus;
    long            lLoopCount = 0;



    //filling the TCP server socket address
    sAddr.sin_family = SL_AF_INET;
    sAddr.sin_port = sl_Htons((unsigned short)usPort);
    sAddr.sin_addr.s_addr = sl_Htonl((unsigned int)addr);

    iAddrSize = sizeof(SlSockAddrIn_t);

    // creating a TCP socket
    iSockID = sl_Socket(SL_AF_INET,SL_SOCK_STREAM, 0);
    if( iSockID < 0 )
    {
        ASSERT_ON_ERROR(TCP_CLIENT_FAILED);
    }

    // connecting to TCP server
    iStatus = sl_Connect(iSockID, ( SlSockAddr_t *)&sAddr, iAddrSize);
    if( iStatus < 0 )
    {
        // error
        ASSERT_ON_ERROR(sl_Close(iSockID));
        ASSERT_ON_ERROR(TCP_CLIENT_FAILED);
    }
    *sock = iSockID;
    g_ucConnectionStatus =1;
    return SUCCESS;
}



//****************************************************************************
//
//! \brief Connecting to a WLAN Accesspoint
//!
//!  This function connects to the required AP (SSID_NAME) with Security
//!  parameters specified in te form of macros at the top of this file
//!
//! \param  None
//!
//! \return  None
//!
//! \warning    If the WLAN connection fails or we don't aquire an IP 
//!            address, It will be stuck in this function forever.
//
//****************************************************************************
static long WlanConnect()
{
    unsigned long marktime;
    SlSecParams_t secParams = {0};
    long lRetVal = 0;
    int i=0;
    char *sid = GetConnectedSid();
	if ( *sid ){
	    secParams.Key  = (_i8*) "";
	    secParams.KeyLen = 0;
	    secParams.Type = SL_SEC_TYPE_OPEN;
	} else {
	    secParams.Key = (signed char*)SECURITY_KEY;
	    secParams.KeyLen = strlen(SECURITY_KEY);
	    secParams.Type = SECURITY_TYPE;
	}

	if( !*sid ){
	    strcpy((char *)sid,(const char *)SSID_NAME);
	}

     UART_PRINT("try to Connect AP[%s] with key[%s]....\n", sid, secParams.Key);

    lRetVal = sl_WlanConnect((signed char*)sid, strlen(sid), 0, &secParams, 0);
    ASSERT_ON_ERROR(lRetVal);

    marktime = sysCurrentTime() ;
    
    // Wait for WLAN Event
    while((!IS_CONNECTED(g_ulStatus)) || (!IS_IP_ACQUIRED(g_ulStatus))) 
    { 
        // Toggle LEDs to Indicate Connection Progress
        GPIO_IF_LedOff(MCU_IP_ALLOC_IND);
        MAP_UtilsDelay(800000);
        GPIO_IF_LedOn(MCU_IP_ALLOC_IND);
        MAP_UtilsDelay(800000);
        if(sysCurrentTime() - marktime > 1000){
            marktime = sysCurrentTime();
            if(i== WLAN_CONNECT_COUNT ){
            UART_PRINT("Connect timeout\n");
            sl_WlanDisconnect();
            return FAILURE;
           }
           i++;
           UART_PRINT(".");
        }
    }
    return SUCCESS;
   
}

static
int compare (void *first, void *second)
{
	Sl_WlanNetworkEntry_t*first_ = (Sl_WlanNetworkEntry_t*)first;
	Sl_WlanNetworkEntry_t*second_ = (Sl_WlanNetworkEntry_t*)second;
    if (first_->rssi > second_->rssi)
        return -1;
    else if (first_->rssi < second_->rssi)
        return 1;
    else
        return 0;
}

static int doScanAccessPoints(void)
{
//
//Connecting to WLAN AP
//
    unsigned char ucpolicyOpt;
    int i,j;
    unsigned short ucIndex;
    long lRetVal;
    union 
    {
        unsigned char ucPolicy[4];
        unsigned int uiPolicyLen;
    } policyVal;
    //
     // enable scan 
     //
     ucpolicyOpt = SL_SCAN_POLICY(1);
     //
     // set scan cycle to 10 seconds 
     //
     policyVal.uiPolicyLen = 10;
     //
     // set scan policy - this starts the scan 
     //
     UART_PRINT("Scan Policy Set\n");
     lRetVal = sl_WlanPolicySet(SL_POLICY_SCAN , ucpolicyOpt,
                                (unsigned char*)(policyVal.ucPolicy), sizeof(policyVal));
     if(lRetVal!=0)
     {
         GPIO_IF_LedOn(MCU_EXECUTE_FAIL_IND);
         UART_PRINT("Unable to set the Scan Policy\n\r");
         return lRetVal;
     }
     UART_PRINT("Delay....\n");
     MAP_UtilsDelay(8000000);
     //
     // get scan results - all 20 entries in one transaction 
     //
     ucIndex = 0;
     //
     // retVal indicates the valid number of entries 
     // The scan results are occupied in netEntries[] 
     //
     
     memset(netEntries, 0, sizeof(netEntries));
     UART_PRINT("Get Wlan Network List...\n");
     lRetVal = sl_WlanGetNetworkList(ucIndex, (unsigned char)WLAN_SCAN_COUNT,
                                     &netEntries[ucIndex]);
     if(lRetVal==0)
     {
         GPIO_IF_LedOn(MCU_EXECUTE_FAIL_IND);
         UART_PRINT("Unable to retreive the network list\n\r");
         return lRetVal;
     }
     UART_PRINT("List %d\n",lRetVal);
	ucIndex = 0;
	scanCount = lRetVal;
    /*
	do
	{
		lRetVal = sl_WlanGetNetworkList(ucIndex,
										(unsigned char)WLAN_SCAN_COUNT/4,
										&netEntries[ucIndex]);
		ucIndex += lRetVal;
	}
	while ((lRetVal == WLAN_SCAN_COUNT/4) && (ucIndex < WLAN_SCAN_COUNT));*/

    InitializeConnectAP(); //Connect Sid Initialize
    UART_PRINT("------------------------------------------------------------------------------------------------\n");
    qsort(netEntries, scanCount, sizeof(Sl_WlanNetworkEntry_t), compare);
    for(i=0; i< scanCount; i++)
    {
          UART_PRINT("ap%2d[%s",i, netEntries[i].ssid);
          for(j=(MAXIMAL_SSID_LENGTH - netEntries[i].ssid_len);j>0;j--){
              UART_PRINT(" ");
          }
          UART_PRINT("], rssi[ %dDB], ",netEntries[i].rssi);
          UART_PRINT("ID[%2x:%2x:%2x:%2x:%2x:%2x]  ", netEntries[i].bssid[0],netEntries[i].bssid[1],netEntries[i].bssid[2],netEntries[i].bssid[3],netEntries[i].bssid[4],netEntries[i].bssid[5]);
          switch(netEntries[i].sec_type){
            case SL_SEC_TYPE_OPEN : 
                UART_PRINT("sectype[ UNSEC   ]\n" );
                if(ConSid[0] &&  (ConRssi > netEntries[i].rssi) ){
                    continue;
                }
                if( strncmp(netEntries[i].ssid,TESTAP_SID_PREFIX,strlen(TESTAP_SID_PREFIX )) == 0) 
                {
                strncpy((char *)ConSid,(const char *)netEntries[i].ssid, netEntries[i].ssid_len);
                ConSid[netEntries[i].ssid_len] =0;
                ConRssi = netEntries[i].rssi;
                }
                break;
            case SL_SEC_TYPE_WEP:
                UART_PRINT("sectype[ WEP     ]\n");
                break;
            case SL_SEC_TYPE_WPA_WPA2:
                UART_PRINT("sectype[ WPA/WPA2]\n");
                break;
            case SL_SEC_TYPE_WPS_PBC:
                UART_PRINT("sectype[ WPS-PBC ]\n");
                break;
            case SL_SEC_TYPE_WPS_PIN:
                UART_PRINT("sectype[ WPS-PIN ]\n");
                break;
                
          }
    }
    UART_PRINT("------------------------------------------------------------------------------------------------\n");
    return 0;


}

//****************************************************************************
//
//! \brief Start simplelink, connect to the ap and run the ping test
//!
//! This function starts the simplelink, connect to the ap and start the ping
//! test on the default gateway for the ap
//!
//! \param[in]  pvParameters - Pointer to the list of parameters that 
//!             can bepassed to the task while creating it
//!
//! \return  None
//
//****************************************************************************
void WlanStationMode( void *pvParameters )
{

    long lRetVal = -1;
    int sock;
    int i,j;
    int retry;
    char *msgBuf;
    int msglen;
     char strbuf[60];
    _u8 macAddressVal[SL_MAC_ADDR_LEN];
    _u8 macAddressLen = SL_MAC_ADDR_LEN;
    char gas[10];

    InitializeAppVariables();
    //
    // Following function configure the device to default state by cleaning
    // the persistent settings stored in NVMEM (viz. connection profiles &
    // policies, power policy etc)
    //
    // Applications may choose to skip this step if the developer is sure
    // that the device is in its default state at start of applicaton
    //
    // Note that all profiles and persistent settings that were done on the
    // device will be lost
    //
    GPIO_IF_LedOn(MCU_ORANGE_LED_GPIO);
    lRetVal = ConfigureSimpleLinkToDefaultState();
    
    if(lRetVal < 0)
    {
        if (DEVICE_NOT_IN_STATION_MODE == lRetVal)
        {
            UART_PRINT("Failed to configure the device in its default state\n\r");
        }

        LOOP_FOREVER();
    }

    UART_PRINT("Device is configured in default state \n\r");

    //
    // Assumption is that the device is configured in station mode already
    // and it is in its default state
    //
    lRetVal = sl_Start(0, 0, 0);
    if (lRetVal < 0 || ROLE_STA != lRetVal)
    {
        UART_PRINT("Failed to start the device \n\r");
        LOOP_FOREVER();
    }
    sl_NetCfgGet(SL_MAC_ADDRESS_GET,NULL,&macAddressLen,(_u8 *)macAddressVal);
    UART_PRINT("mac addr is %x:%x:%x:%x:%x:%x", macAddressVal[0],macAddressVal[1],macAddressVal[2],macAddressVal[3],macAddressVal[4],macAddressVal[5]);

    UART_PRINT("Device started as STATION \n\r");
RETRY:
    doScanAccessPoints();
    if ( doGatherTestAP()!= SUCCESS)
    	goto RETRY;
    
    UART_PRINT("start Connecting Wlan ...\n");
    if(GET_STATUS_BIT(g_ulStatus, STATUS_BIT_CONNECTION)){
        lRetVal = SUCCESS;
    }else{
        lRetVal = WlanConnect();
    }
    if(lRetVal < 0)
    {
        UART_PRINT("Failed to establish connection w/ an AP \n\r");
        goto RETRY;
        //LOOP_FOREVER();
    }
    UART_PRINT("Connection established w/ AP(%s) and IP is aquired \n\r",GetConnectedSid());
    UART_PRINT("TCP Connect...! \n\r");

    if(!g_ucConnectionStatus){
        retry =3;
        UART_PRINT("retry count= %d\n\r", retry);
        while(retry){
            UART_PRINT("Dest(%x), PORT(%x)\n",g_ulDestinationIp, PORT_NUM);
            lRetVal = tcpClientConnect(g_ulDestinationIp, PORT_NUM, &socketID);
            if(lRetVal < 0)
            {
                UART_PRINT("TCP Client failed\n\r");
                retry--;
                continue;
            }else{
                UART_PRINT("Tcp Server[%x : %x] Connected...\n",g_ulDestinationIp, PORT_NUM);
                break;
            }
        }
        if(retry == 0) 
            goto RETRY;
    }


#if 0
    msglen = scanCount*sizeof(Sl_WlanNetworkEntry_t);
    memcpy(tcpSendBuf,netEntries,msglen);
#endif
    memset(tcpSendBuf,0, BUF_SIZE);

    //strcpy(tcpSendBuf,(const char *)"#DEVINFO:IT,id_001,0,");
	strcpy(tcpSendBuf,(const char *)"#DEVINFO:IT,");
    sprintf(strbuf,"%x%x%x%x%x%x,0,",macAddressVal[0],macAddressVal[1],macAddressVal[2],macAddressVal[3],macAddressVal[4],macAddressVal[5]);
    strcat(tcpSendBuf,strbuf);
    for(i=0; i<3; i++)
    {
		if( strncmp(testAP[i].ssid,TESTAP_SID_PREFIX,strlen(TESTAP_SID_PREFIX)) == 0)
		{
	    	strcat(tcpSendBuf,testAP[i].ssid);
	        strcat(tcpSendBuf,"&");
	        sprintf(strbuf,"%d",testAP[i].rssi);
	        strcat(tcpSendBuf, strbuf);
	        strcat(tcpSendBuf,"&");
	        sprintf(strbuf,"%d",2400);
	        strcat(tcpSendBuf,strbuf);
	        if(i != 2) strcat(tcpSendBuf,",");
    	}
    }
    sprintf(strbuf,",,,");
    strcat(tcpSendBuf,strbuf);

	SetPic();
	memset(gas, 0, sizeof(gas));
	for(j=0; j<sizeof(gas); j++)
	{
		gas[j] = GetPic();
		if(gas[j] == '\r')
			break;
	}

    strcat(tcpSendBuf,gas);

    UART_PRINT("send msg(%s)",tcpSendBuf);
    UART_PRINT("\n\r");
    lRetVal = sendTcpMessage(socketID,tcpSendBuf, strlen(tcpSendBuf) );

    if(lRetVal<0){
        g_ucConnectionStatus =0;
    }else{
       // UART_PRINT("send sucess size[%d]\n", msglen);
    }

    rcvTcpMessage(socketID,tcpRcvBuf,30);
    UART_PRINT("rcv msg(%s)",tcpRcvBuf);
    PicUartn(tcpRcvBuf,30);
    UART_PRINT("\n\r");

    osi_Sleep(1000);
    goto RETRY;
        

    // power off the network processor
    //
    lRetVal = sl_Stop(SL_STOP_TIMEOUT);

    LOOP_FOREVER();
    
}
//*****************************************************************************
//
//! Application startup display on UART
//!
//! \param  none
//!
//! \return none
//!
//*****************************************************************************
static void
DisplayBanner(char * AppName)
{

    UART_PRINT("\n\n\n\r");
    UART_PRINT("\t\t ************************************************************\n\r");
    UART_PRINT("\t\t    CC3200 %s Application       \n\r", AppName);
    UART_PRINT("\t\t ************************************************************\n\r");
    UART_PRINT("\n\n\n\r");
}
//*****************************************************************************
//
//! \brief  Board Initialization & Configuration
//!
//! \param  None
//!
//! \return None
//
//*****************************************************************************
static void
BoardInit(void)
{
// In case of TI-RTOS vector table is initialize by OS itself
#ifndef USE_TIRTOS
    //
    // Set vector table base
    //
#if defined(ccs) || defined(gcc)
    MAP_IntVTableBaseSet((unsigned long)&g_pfnVectors[0]);
#endif
#if defined(ewarm)
    MAP_IntVTableBaseSet((unsigned long)&__vector_table);
#endif
#endif //USE_TIRTOS

    //
    // Enable Processor
    //
    MAP_IntMasterEnable();
    MAP_IntEnable(FAULT_SYSTICK);

    PRCMCC3200MCUInit();
}


//*****************************************************************************
//                            MAIN FUNCTION
//*****************************************************************************
void main()
{
    long lRetVal = -1;

    //
    // Board Initialization
    //
    BoardInit();
    
    //
    // configure the GPIO pins for LEDs,UART
    //
    PinMuxConfig();

    //
    // Configure the UART
    //
#ifndef NOTERM
    InitTerm();
#endif  //NOTERM
    //
    // Display Application Banner
    //
    DisplayBanner(APPLICATION_NAME);
    
    //
    // Configure all 3 LEDs
    //
    GPIO_IF_LedConfigure(LED1|LED2|LED3);

    // switch off all LEDs
    GPIO_IF_LedOff(MCU_ALL_LED_IND);
    
    //
    // Start the SimpleLink Host
    //
    GPIO_IF_LedOn(MCU_ON_IND);
    lRetVal = VStartSimpleLinkSpawnTask(SPAWN_TASK_PRIORITY);
    if(lRetVal < 0)
    {
        ERR_PRINT(lRetVal);
        LOOP_FOREVER();
    }

    doInputConfiguration();


    //
    // Start the WlanStationMode task
    //
    lRetVal = osi_TaskCreate( WlanStationMode, \
                                (const signed char*)"Wlan Station Task", \
                                OSI_STACK_SIZE+1024, NULL, 1, NULL );
    if(lRetVal < 0)
    {
        ERR_PRINT(lRetVal);
        LOOP_FOREVER();
    }

    //
    // Start the task scheduler
    //
    osi_start();
  }

//*****************************************************************************
//
// Close the Doxygen group.
//! @}
//
//*****************************************************************************
