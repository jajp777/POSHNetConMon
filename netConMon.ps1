$Global:decodedPackets = [System.Collections.ArrayList]@()

Function getService( $port )
{
	$protocols = foreach( $line in $serviceFile )
	{            
		# not empty lines
		if( -not $line )	{ continue }

		# split lines into name, port+proto, alias+comment
		$serviceName, $portAndProtocol, $aliasesAndComments = $line.Split(' ', [StringSplitOptions]'RemoveEmptyEntries')
		# split port+proto into port, proto
		$portNumber, $protocolName = $portAndProtocol.Split("/")            

		if( $portNumber -eq $port )
		{
			return $serviceName
		}
	}
}

Function NetworkToHostUInt16( $address )
{
	[Array]::Reverse( $address )
	return [BitConverter]::ToUInt16( $address, 0 )
}
Function NetworkToHostUInt32( $address )
{
	[Array]::Reverse( $address )
	return [BitConverter]::ToUInt32( $address, 0 )
}
Function ByteToString( $address )
{
	$AsciiEncoding = New-Object System.Text.ASCIIEncoding
	return $AsciiEncoding.GetString( $address )
    }

function capturePackets{
    param( [String]$LocalIP = "NotSpecified", [String]$ScanIP="all", [String]$Protocol = "all", `
		    [String]$Port="all", [Int]$Seconds = 0, [switch]$ResolveHosts, [switch]$Help )
    
    $byteIn = New-Object Byte[] 4			# source
    $byteOut = New-Object Byte[] 4			# destination
    $byteData = New-Object Byte[] 4096

    $byteIn[0] = 1  						# enable promiscuous mode
    $byteIn[1-3] = 0
    $byteOut[0-3] = 0

    # Opens socket
    $Socket = New-Object System.Net.Sockets.Socket( [Net.Sockets.AddressFamily]::InterNetwork, [Net.Sockets.SocketType]::Raw, [Net.Sockets.ProtocolType]::IP )
    $Socket.SetSocketOption( "IP", "HeaderIncluded", $true )
    # Packet buffer
    $Socket.ReceiveBufferSize = 1024000
    # Create IP endpoint
    $Endpoint = New-Object System.Net.IPEndpoint( [Net.IPAddress]"$LocalIP", 0 )
    $Socket.Bind( $Endpoint )
    # Promiscuous mode
    [void]$Socket.IOControl( [Net.Sockets.IOControlCode]::ReceiveAll, $byteIn, $byteOut )


    $packets = @()							# array for packets
    $running = $true
    $count = 1
    while( $running )
    {
        if( -not $Socket.Available )
	    {
		    start-sleep -milliseconds 300
		    continue
	    }
    # receive data
	    $rData = $Socket.Receive( $byteData, 0, $byteData.length, [Net.Sockets.SocketFlags]::None )
        $packetTime = Get-Date
        decodePacket $rData $byteData $packetTime

        
    }
    
    
}
function decodePacket{
        param( [int]$packet,[byte[]]$byteData,[DateTime]$packetTime)


        $MemoryStream = New-Object System.IO.MemoryStream( $byteData, 0, $packet )
	    $BinaryReader = New-Object System.IO.BinaryReader( $MemoryStream )

	    # b1 - version & header length
	    $VerHL = $BinaryReader.ReadByte( )
	    # b2 - type of service
	    $TOS= $BinaryReader.ReadByte( )
	    # b3,4 - total length
	    $Length = NetworkToHostUInt16 $BinaryReader.ReadBytes( 2 )
	    # b5,6 - identification
	    $Ident = NetworkToHostUInt16 $BinaryReader.ReadBytes( 2 )
	    # b7,8 - flags & offset
	    $FlagsOff = NetworkToHostUInt16 $BinaryReader.ReadBytes( 2 )
	    # b9 - time to live
	    $TTL = $BinaryReader.ReadByte( )
	    # b10 - protocol
	    $ProtocolNumber = $BinaryReader.ReadByte( )
	    # b11,12 - header checksum
	    $Checksum = [Net.IPAddress]::NetworkToHostOrder( $BinaryReader.ReadInt16() )
	    # b13-16 - source ip address
	    $SourceIP = $BinaryReader.ReadUInt32( )
	    $SourceIP = [System.Net.IPAddress]$SourceIP
	    # b17-20 - destination ip address
	    $DestinationIP = $BinaryReader.ReadUInt32( )
	    $DestinationIP = [System.Net.IPAddress]$DestinationIP

	    # get ip version (bits 0-3)
	    $ipVersion = [int]"0x$(('{0:X}' -f $VerHL)[0])"
	    # get header length (bits 4-7)
	    $HeaderLength = [int]"0x$(('{0:X}' -f $VerHL)[1])" * 4

	    # header includes Options...
	    if($HeaderLength -gt 20)
	    {
		    [void]$BinaryReader.ReadBytes( $HeaderLength - 20 )  # should probably do something with this later
	    }
	
	    $Data = ""
	    $TCPFlagsString = @()  				# make this an array
	    $TCPWindow = ""
	    $SequenceNumber = ""
	
	    switch( $ProtocolNumber )
	    {
		    1 {  # ICMP
			    $ProtocolDesc = "ICMP"
			    $sourcePort = [uint16]0
			    $destPort = [uint16]0
			    $ICMPType = $BinaryReader.ReadByte()
			    $ICMPCode = $BinaryReader.ReadByte()
			    switch( $ICMPType )
			    {
				    0	{	$ICMPTypeDesc = "Echo reply"; break }
				    3	{	$ICMPTypeDesc = "Destination unreachable"
						    switch( $ICMPCode )
						    {
							    0	{	$ICMPCodeDesc = "Network not reachable"; break }
							    1	{	$ICMPCodeDesc = "Host not reachable"; break }
							    2	{	$ICMPCodeDesc = "Protocol not reachable"; break }
							    3	{	$ICMPCodeDesc = "Port not reachable"; break }
							    4	{	$ICMPCodeDesc = "Fragmentation needed"; break }
							    5	{	$ICMPCodeDesc = "Route not possible"; break }
							    13	{	$ICMPCodeDesc = "Administratively not possible"; break }
							    default	{	$ICMPCodeDesc = "Other ($_)" }
						    }
						    break
				    }
				    4	{	$ICMPTypeDesc = "Source quench"; break }
				    5	{	$ICMPTypeDesc = "Redirect"; break }
				    8	{	$ICMPTypeDesc = "Echo request"; break }
				    9	{	$ICMPTypeDesc = "Router advertisement"; break }
				    10	{	$ICMPTypeDesc = "Router solicitation"; break }
				    11	{	$ICMPTypeDesc = "Time exceeded"
						    switch( $ICMPCode )
						    {
							    0	{	$ICMPCodeDesc = "TTL exceeded"; break }
							    1	{	$ICMPCodeDesc = "While fragmenting exceeded"; break }
							    default	{	$ICMPCodeDesc = "Other ($_)" }
						    }
						    break
				    }
				    12	{	$ICMPTypeDesc = "Parameter problem"; break }
				    13	{	$ICMPTypeDesc = "Timestamp"; break }
				    14	{	$ICMPTypeDesc = "Timestamp reply"; break }
				    15	{	$ICMPTypeDesc = "Information request"; break }
				    16	{	$ICMPTypeDesc = "Information reply"; break }
				    17	{	$ICMPTypeDesc = "Address mask request"; break }
				    18	{	$ICMPTypeDesc = "Address mask reply"; break }
				    30	{	$ICMPTypeDesc = "Traceroute"; break }
				    31	{	$ICMPTypeDesc = "Datagram conversion error"; break }
				    32	{	$ICMPTypeDesc = "Mobile host redirect"; break }
				    33	{	$ICMPTypeDesc = "Where-are-you"; break }
				    34	{	$ICMPTypeDesc = "I-am-here"; break }
				    35	{	$ICMPTypeDesc = "Mobile registration request"; break }
				    36	{	$ICMPTypeDesc = "Mobile registration reply"; break }
				    37	{	$ICMPTypeDesc = "Domain name request"; break }
				    38	{	$ICMPTypeDesc = "Domain name reply"; break }
				    39	{	$ICMPTypeDesc = "SKIP"; break }
				    40	{	$ICMPTypeDesc = "Photuris"; break }
				    41	{	$ICMPTypeDesc = "Experimental mobility protocol"; break }
				    default	{	$ICMPTypeDesc = "Other ($_)" }
			    }
			    $ICMPChecksum = [System.Net.IPAddress]::NetworkToHostOrder($BinaryReader.ReadInt16())
			    $Data = ByteToString $BinaryReader.ReadBytes($Length - ($HeaderLength - 32))
			    break
			    }
		    2 {  # IGMP
			    $ProtocolDesc = "IGMP"
			    $sourcePort = [uint16]0
			    $destPort = [uint16]0
			    $IGMPType = $BinaryReader.ReadByte()
			    $IGMPMaxRespTime = $BinaryReader.ReadByte()
			    $IGMPChecksum = [System.Net.IPAddress]::NetworkToHostOrder($BinaryReader.ReadInt16())
			    $Data = ByteToString $BinaryReader.ReadBytes($Length - ($HeaderLength - 32))
			    break
			    }
		    6 {  # TCP
			    $ProtocolDesc = "TCP"
			    $sourcePort = NetworkToHostUInt16 $BinaryReader.ReadBytes(2)
			    $destPort = NetworkToHostUInt16 $BinaryReader.ReadBytes(2)
			    $serviceDesc = getService( $destPort )
			    $SequenceNumber = NetworkToHostUInt32 $BinaryReader.ReadBytes(4)
			    $AckNumber = NetworkToHostUInt32 $BinaryReader.ReadBytes(4)
			    $TCPHeaderLength = [int]"0x$(('{0:X}' -f $BinaryReader.ReadByte())[0])" * 4
			    $TCPFlags = $BinaryReader.ReadByte()
			    switch( $TCPFlags )
			    {
				    { $_ -band $TCPFIN }	{ $TCPFlagsString += "<FIN>" }
				    { $_ -band $TCPSYN }	{ $TCPFlagsString += "<SYN>" }
				    { $_ -band $TCPRST }	{ $TCPFlagsString += "<RST>" }
				    { $_ -band $TCPPSH }	{ $TCPFlagsString += "<PSH>" }
				    { $_ -band $TCPACK }	{ $TCPFlagsString += "<ACK>" }
				    { $_ -band $TCPURG }	{ $TCPFlagsString += "<URG>" }
			    }
			    $TCPWindow = NetworkToHostUInt16 $BinaryReader.ReadBytes(2)
			    $TCPChecksum = [System.Net.IPAddress]::NetworkToHostOrder($BinaryReader.ReadInt16())
			    $TCPUrgentPointer = NetworkToHostUInt16 $BinaryReader.ReadBytes(2)
			    if( $TCPHeaderLength -gt 20 )  # get to start of data...
			    {
				    [void]$BinaryReader.ReadBytes($TCPHeaderLength - 20)
			    }
			    # if SYN flag is set, sequence number is initial, then first data octet is ISN + 1
			    if ($TCPFlags -band $TCPSYN)
			    {
				    $ISN = $SequenceNumber
				    #$SequenceNumber = $BinaryReader.ReadBytes(1)
				    [void]$BinaryReader.ReadBytes(1)
			    }
			    $Data = ByteToString $BinaryReader.ReadBytes($Length - ($HeaderLength + $TCPHeaderLength))
			    break
			    }
		    17 {  # UDP
			    $ProtocolDesc = "UDP"
			    $sourcePort = NetworkToHostUInt16 $BinaryReader.ReadBytes(2)
			    $destPort = NetworkToHostUInt16 $BinaryReader.ReadBytes(2)
			    $serviceDesc = getService( $destPort )
			    $UDPLength = NetworkToHostUInt16 $BinaryReader.ReadBytes(2)
			    [void]$BinaryReader.ReadBytes(2)
			    # subtract udp header length (2 octets) and convert octets to bytes
			    $Data = ByteToString $BinaryReader.ReadBytes(($UDPLength - 2) * 4)
			    break
			    }
		    default {
			    $ProtocolDesc = "Other ($_)"
			    $sourcePort = 0
			    $destPort = 0
			    }
	    }
	
	    $BinaryReader.Close( )
	    $memorystream.Close( )
	    $Data = $Data.toCharArray( 0, $Data.length )

	    # resolve IP addresses to hostnames...
	    if( $ResolveHosts )
	    {
		    # $DestinationHostName = ([System.Net.DNS]::GetHostEntry($DestinationIP.IPAddressToString)).Hostname
		    $DestinationHostName = resolve( $DestinationIP )
		    # $SourceHostName = ([System.Net.DNS]::GetHostEntry($SourceIP.IPAddressToString)).Hostname
		    $SourceHostName = resolve( $SourceIP )
	    }

        $properties = @{'Time'=$packetTime;
                                    'Version'=$ipVersion;
                                    'Protocol'=$ProtocolDesc;
                                    'Destination IP'=$DestinationIP;
                                    'Source IP'=$SourceIP;
                                    'Destination Port'=$destPort;
                                    'Source Port'=$sourcePort;
                                    'Type'='';
                                    'Code'='';
                                    'Max Response Time'='';
                                    'Sequence Number'='';
                                    'Acknowledgement Number'='';
                                    'Window'='';
                                    'Flags'='';
                                    'Service'='';
                                    'Data'=''}
        $packetInfo = New-Object –TypeName PSObject –Prop $properties
        $packetInfo.PSObject.TypeNames.Insert(0,'Packet')



		switch( $ProtocolDesc )
		{
			"ICMP"	{
                    $packetInfo.'Type'="$ICMPType - $ICMPTypeDesc"
                    $packetInfo.'Code'="$ICMPCode - $ICMPCodeDesc"            
					break
				}
			"IGMP"	{                
                    $packetInfo.'Type'=$IGMPType
                    $packetInfo.'Max Response Time'="$($IGMPMaxRespTime*100)ms"             
					break
				}
			"TCP"	{
                    $packetInfo.'Sequence Number'=$SequenceNumber
                    $packetInfo.'Acknowledgement Number'=$AckNumber
                    $packetInfo.'Window'=$TCPWindow
                    $packetInfo.'Flags'=$TCPFlagsString
                    $packetInfo.'Service'=$serviceDesc          
					break
				}
			"UDP"	{

                    $packetInfo.'Service'=$serviceDesc
					break
				}
		}
             
		for( $index = 0; $index -lt $Data.length; $index++ )
		{
			# eliminate non ascii characters...
			if( $Data[$index] -lt 33 -or $Data[$index] -gt 126 )
			{
				$Data[$index] = '.'
			}
		} 
        $packetInfo.Data = -join [char[]]$Data
        $decodedPackets.Add($packetInfo)
	
		Write-Host "----------------------------------------------------------------------"
		#$decodedPackets	    
}

function analyzePacket{
    





}

capturePackets "192.168.1.153"