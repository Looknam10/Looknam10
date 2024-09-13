#include "ns3/mobility-module.h"
#include "ns3/nstime.h"
#include "ns3/core-module.h"
#include "ns3/network-module.h"
#include "ns3/internet-module.h"
#include "ns3/point-to-point-module.h"
#include "ns3/applications-module.h"
#include "ns3/ipv4-global-routing-helper.h"
#include "ns3/netanim-module.h"
#include "ns3/flow-monitor.h"
#include "ns3/flow-monitor-helper.h"
#include "ns3/flow-monitor-module.h"

#define TCP_SINK_PORT 9000
#define UDP_SINK_PORT 9001

// Experimental parameters
#define MAX_BULK_BYTES 100000
#define DDOS_RATE "1Mb/s"
#define MAX_SIMULATION_TIME 10

// Number of Bots for DDoS
#define NUMBER_OF_BOTS 100
#define NUMBER_OF_EXTRA_NODES 4

using namespace ns3;

NS_LOG_COMPONENT_DEFINE("TwoTierDDoSAttack");

int main(int argc, char *argv[])
{
    CommandLine cmd;
    cmd.Parse(argc, argv);

    Time::SetResolution(Time::NS);
    LogComponentEnable("UdpEchoClientApplication", LOG_LEVEL_INFO);
    LogComponentEnable("UdpEchoServerApplication", LOG_LEVEL_INFO);

    // Core nodes (Tier 1)
    NodeContainer coreNodes;
    coreNodes.Create(2); // Core node 0 and 1

    // Subnet nodes (Tier 2)
    NodeContainer tier2Nodes;
    tier2Nodes.Create(6); // 6 nodes for tier 2, which can include servers or clients

    // Bot nodes for DDoS
    NodeContainer botNodes;
    botNodes.Create(NUMBER_OF_BOTS);

    // Extra user nodes
    NodeContainer extraNodes;
    extraNodes.Create(NUMBER_OF_EXTRA_NODES);

    // Define Point-To-Point Links and their Parameters
    PointToPointHelper coreLink, tier2Link, botLink, extraLink;
    coreLink.SetDeviceAttribute("DataRate", StringValue("100Mbps"));
    coreLink.SetChannelAttribute("Delay", StringValue("1ms"));

    tier2Link.SetDeviceAttribute("DataRate", StringValue("10Mbps"));
    tier2Link.SetChannelAttribute("Delay", StringValue("1ms"));

    botLink.SetDeviceAttribute("DataRate", StringValue("50Mbps"));
    botLink.SetChannelAttribute("Delay", StringValue("2ms"));

    extraLink.SetDeviceAttribute("DataRate", StringValue("10Mbps"));
    extraLink.SetChannelAttribute("Delay", StringValue("1ms"));

    // Install Point-To-Point Connections between Core Nodes and Tier 2 Nodes
    NetDeviceContainer coreDevices, tier2Devices, botDevices[NUMBER_OF_BOTS], extraDevices[NUMBER_OF_EXTRA_NODES];

    // Connect core node 0 to core node 1
    coreDevices = coreLink.Install(coreNodes.Get(0), coreNodes.Get(1));

    // Connect core node 1 to each of the Tier 2 nodes
    for (uint32_t i = 0; i < tier2Nodes.GetN(); ++i)
    {
        tier2Devices = tier2Link.Install(coreNodes.Get(1), tier2Nodes.Get(i));
    }

    // Connect bot nodes to core node 0
    for (int i = 0; i < NUMBER_OF_BOTS; ++i)
    {
        botDevices[i] = botLink.Install(botNodes.Get(i), coreNodes.Get(0));
    }

    // Connect extra user nodes to a specific Tier 2 node
    for (int i = 0; i < NUMBER_OF_EXTRA_NODES; ++i)
    {
        extraDevices[i] = extraLink.Install(tier2Nodes.Get(2), extraNodes.Get(i)); // Connecting to node 2 of tier 2
    }

    // Enable packet capture for Wireshark
    coreLink.EnablePcapAll("two_tier_core_traffic");
    tier2Link.EnablePcapAll("two_tier_tier2_traffic");
    botLink.EnablePcapAll("two_tier_ddos_traffic");
    extraLink.EnablePcapAll("two_tier_extra_traffic");

    // Install Internet Stack and Assign IP addresses
    InternetStackHelper stack;
    stack.Install(coreNodes);
    stack.Install(tier2Nodes);
    stack.Install(botNodes);
    stack.Install(extraNodes);

    Ipv4AddressHelper address;
    address.SetBase("10.1.1.0", "255.255.255.0");

    Ipv4InterfaceContainer coreInterfaces, tier2Interfaces[6], botInterfaces[NUMBER_OF_BOTS], extraInterfaces[NUMBER_OF_EXTRA_NODES];

    coreInterfaces = address.Assign(coreDevices);
    address.NewNetwork();

    // Assign IPs to Tier 2 nodes
    for (uint32_t i = 0; i < tier2Nodes.GetN(); ++i)
    {
        tier2Interfaces[i] = address.Assign(tier2Devices);
        address.NewNetwork();
    }

    // Assign IPs to bot nodes
    for (int i = 0; i < NUMBER_OF_BOTS; ++i)
    {
        botInterfaces[i] = address.Assign(botDevices[i]);
        address.NewNetwork();
    }

    // Assign IPs to extra nodes
    for (int i = 0; i < NUMBER_OF_EXTRA_NODES; ++i)
    {
        extraInterfaces[i] = address.Assign(extraDevices[i]);
        address.NewNetwork();
    }

    // Set up DDoS Application Behavior (UDP Attack)
    OnOffHelper onoff("ns3::UdpSocketFactory", Address(InetSocketAddress(tier2Interfaces[3].GetAddress(1), UDP_SINK_PORT))); // Assuming attacks on node 3 of tier 2
    onoff.SetConstantRate(DataRate(DDOS_RATE));
    onoff.SetAttribute("OnTime", StringValue("ns3::ConstantRandomVariable[Constant=30]"));
    onoff.SetAttribute("OffTime", StringValue("ns3::ConstantRandomVariable[Constant=0]"));

    ApplicationContainer onOffApp[NUMBER_OF_BOTS];
    for (int k = 0; k < NUMBER_OF_BOTS; ++k)
    {
        onOffApp[k] = onoff.Install(botNodes.Get(k));
        onOffApp[k].Start(Seconds(0.0));
        onOffApp[k].Stop(Seconds(MAX_SIMULATION_TIME));
    }

    // Legitimate TCP traffic application (BulkSend) on a core node
    BulkSendHelper bulkSend("ns3::TcpSocketFactory", InetSocketAddress(tier2Interfaces[3].GetAddress(1), TCP_SINK_PORT));
    bulkSend.SetAttribute("MaxBytes", UintegerValue(MAX_BULK_BYTES));
    ApplicationContainer bulkSendApp = bulkSend.Install(coreNodes.Get(0));
    bulkSendApp.Start(Seconds(0.0));
    bulkSendApp.Stop(Seconds(MAX_SIMULATION_TIME));

    // TCP Sink Application on the server side
    PacketSinkHelper TCPsink("ns3::TcpSocketFactory", InetSocketAddress(Ipv4Address::GetAny(), TCP_SINK_PORT));
    ApplicationContainer TCPSinkApp = TCPsink.Install(tier2Nodes.Get(3)); // Targeting node 3 of tier 2
    TCPSinkApp.Start(Seconds(0.0));
    TCPSinkApp.Stop(Seconds(MAX_SIMULATION_TIME));

    Ipv4GlobalRoutingHelper::PopulateRoutingTables();

    // Simulation NetAnim configuration and node placement
    MobilityHelper mobility;
    mobility.SetPositionAllocator("ns3::GridPositionAllocator",
                                  "MinX", DoubleValue(0.0), "MinY", DoubleValue(0.0),
                                  "DeltaX", DoubleValue(5.0), "DeltaY", DoubleValue(10.0),
                                  "GridWidth", UintegerValue(3), "LayoutType", StringValue("RowFirst"));
    mobility.SetMobilityModel("ns3::ConstantPositionMobilityModel");
    mobility.Install(coreNodes);
    mobility.Install(tier2Nodes);
    mobility.Install(botNodes);
    mobility.Install(extraNodes);

    AnimationInterface anim("TwoTierDDoSSim.xml");

    // Load icons into NetAnim
    uint32_t coreNodeIcon = anim.AddResource("icon/core.png");
    uint32_t tier2NodeIcon = anim.AddResource("icon/tier2.png");
    uint32_t botIcon = anim.AddResource("icon/bot.png");
    uint32_t extraNodeIcon = anim.AddResource("icon/user.png");

    // Assign icons to core nodes
    anim.UpdateNodeImage(coreNodes.Get(0)->GetId(), coreNodeIcon);
    anim.UpdateNodeImage(coreNodes.Get(1)->GetId(), coreNodeIcon);

    // Assign icons to tier 2 nodes
    for (uint32_t i = 0; i < tier2Nodes.GetN(); ++i)
    {
        anim.Update


