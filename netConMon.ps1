param([string]$IP,[string]$seconds)

# load the appropriate assemblies 
[void][Reflection.Assembly]::LoadWithPartialName(“System.Windows.Forms”) 
[void][Reflection.Assembly]::LoadWithPartialName(“System.Windows.Forms.DataVisualization")
# Variable $ File Init
$Global:decodedPackets = [System.Collections.ArrayList]@()
$Script:packetCount = 0
$Script:analyzedConnections = @{}
$Script:serviceCounts = @{}
$Script:protocolCounts = @{}
$Script:timeData = @{}
$Script:dataCounts = @{}
$Script:localIP = $IP
# Services                     
$serviceFile = [IO.File]::ReadAllText("$env:windir\System32\drivers\etc\services") -split
([Environment]::NewLine) -notlike "#*"

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

Function capturePackets{
    param([int]$seconds=30 )
    
    $byteIn = New-Object Byte[] 4			# source
    $byteOut = New-Object Byte[] 4			# destination
    $byteData = New-Object Byte[] 8192

    $byteIn[0] = 1  						# enable promiscuous mode
    $byteIn[1-3] = 0
    $byteOut[0-3] = 0

    # Opens socket
    $Socket = New-Object System.Net.Sockets.Socket( [Net.Sockets.AddressFamily]::InterNetwork, [Net.Sockets.SocketType]::Raw, [Net.Sockets.ProtocolType]::IP )
    $Socket.SetSocketOption( "IP", "HeaderIncluded", $true )
    # Packet buffer
    #$Socket.ReceiveBufferSize = 1024000
    $Socket.ReceiveBufferSize = 819200
    # Create IP endpoint
    $Endpoint = New-Object System.Net.IPEndpoint( [Net.IPAddress]"$localIP", 0 )
    $Socket.Bind( $Endpoint )
    # Promiscuous mode
    [void]$Socket.IOControl( [Net.Sockets.IOControlCode]::ReceiveAll, $byteIn, $byteOut )


    $packets = @()							# array for packets
    $running = $true
    $count = 1
    $runTime = New-TimeSpan -Seconds $seconds
    $sw = [diagnostics.stopwatch]::StartNew()
    while($sw.elapsed -lt $runTime)
    {
        Write-Progress -activity "Capturing Packets" -status "Time Left: " -SecondsRemaining($seconds - ($sw.ElapsedMilliseconds/1000))
        if( -not $Socket.Available )
	    {
		    start-sleep -milliseconds 300
		    continue
	    }
        # receive data
	    #$rData = $Socket.Receive( $byteData, 0, $byteData.length, [Net.Sockets.SocketFlags]::None )
	    $rData = $Socket.Receive($byteData)
        
        $packetTime = Get-Date
        decodePacket $rData $byteData $packetTime
        $packetCount++          
    }
    Write-Progress -Completed -Activity "Capturing Packets"    
    Write-Host "Total Packets Captured: $packetCount"    
}
Function decodePacket{
        param( [int]$packet,[byte[]]$byteData,[DateTime]$packetTime)
        
        $MemoryStream = New-Object System.IO.MemoryStream( $byteData, 0, $packet )
        $packetSize = $byteData.Length
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
                if($serviceDesc -eq $null){ $serviceDesc = getService( $sourcePort )}
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
                if($serviceDesc -eq $null){ $serviceDesc = getService( $sourcePort )}
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

        $properties = @{'Packet Number'=$packetNumber;
                                    'Time'=$packetTime;
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
                                    'Data'='';
                                    'Data Size'=''}
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
        #$packetSize = $Data.length
        <#             
		for( $index = 0; $index -lt $Data.length; $index++ )
		{
			# eliminate non ascii characters...
			if( $Data[$index] -lt 33 -or $Data[$index] -gt 126 )
			{
                if($Data[$index] -eq 0){$packetSize--}
				$Data[$index] = '.'
			}
		}#>
        <#
        for( $index = $byteData.length-1; $index -gt 0; $index-- )
		{
			if($byteData[$index] -eq 0){$packetSize--}else{$index = 0}			
		}#>
        
        #if($packetSize -eq 0){$packetSize = $packetInfo.'Window'}
        $packetInfo.'Data Size' = $packetSize
        $packetInfo.Data = -join [char[]]$Data
        
        #$decodedPackets.Add($packetInfo)
	    analyzePacket $packetInfo
		
		#$decodedPackets	    
}
Function analyzePacket{
    param($packet)
    
    #$packet
    
    $destinationIP = $packet.'Destination IP'.IPAddressToString
    $sourceIP = $packet.'Source IP'.IPAddressToString
    #Write-Host "$destinationIP - $sourceIP"
                  
    if($destinationIP -eq $localIP){
        $tempIP = $sourceIP
        $sourceIP = $destinationIP
        $destinationIP = $tempIP
    }

    if($packet.'Service' -eq $null -or $packet.'Service' -eq ''){
        $serviceType = 'Unknown'
        #Write-Host "--" $log.'Service' "--"
    }else{
        $serviceType = $packet.'Service'
    }
    if(!$serviceCounts.ContainsKey($serviceType)){
        $serviceCounts.Add($serviceType,1)
    }else{
        $serviceCounts.$serviceType++
    }

    $protocolType = $packet.Protocol
    if(!$protocolCounts.ContainsKey($protocolType)){
        $protocolCounts.Add($protocolType,1)
    }else{
        $protocolCounts.$protocolType++
    }

    if(!$dataCounts.ContainsKey($destinationIP)){
        $dataCounts.Add($destinationIP,1)
    }else{
        $dataCounts.$destinationIP++
    }
    
    $hr = $packet.'Time'.Hour
    $min = $packet.'Time'.Minute
    $sec = $packet.'Time'.Second
    <#
    if($sec -lt 16){
        $time = (Get-Date -Hour $hr -Minute $min -Second 0).ToString('hh:mm:ss tt')
    }elseif($sec -eq 15 -and $sec -lt 31){
        $time = (Get-Date -Hour $hr -Minute $min -Second 15)
    }elseif($sec -eq 31 -and $sec -lt 46){
        $time = (Get-Date -Hour $hr -Minute $min -Second 30)
    }else{
        $time = (Get-Date -Hour $hr -Minute $min -Second 45)
    }#>

    $time = (Get-Date -Hour $hr -Minute $min -Second $sec).ToString('hh:mm:ss')
    if(!$timeData.ContainsKey($time)){
        $timeData.Add($time,1)  
    }else{
        $timeData.$time++
    }

}


Function buildCharts{
# create chart object 
$Script:dataChart = New-object System.Windows.Forms.DataVisualization.Charting.Chart 
$dataChart.Width = 700 
$dataChart.Height = 400 
$dataChart.Left = 40 
$dataChart.Top = 30

# create a chartarea to draw on and add to chart 
$dataChartArea = New-Object System.Windows.Forms.DataVisualization.Charting.ChartArea 
$dataChart.ChartAreas.Add($dataChartArea)

# add data to chart 

$dataChartData = $dataCounts.GetEnumerator() | sort -Property Value -Descending | select -First 3

[void]$dataChart.Titles.Add(“Top 3 Most Active Connections”) 
$dataChartArea.AxisX.Title = “IP Address” 
$dataChartArea.AxisY.Title = “Packets”

[void]$dataChart.Series.Add(“Data”) 
$dataChart.Series[“Data”].Points.DataBindXY($dataChartData.Name, $dataChartData.Value)
#$dataChart.Series[“Data”].Points.DataBindXY($tempdataChartData.Keys, $tempdataChartData.Values)

# display the chart on a form 
$dataChart.Anchor = [System.Windows.Forms.AnchorStyles]::Bottom -bor [System.Windows.Forms.AnchorStyles]::Right -bor 
                [System.Windows.Forms.AnchorStyles]::Top -bor [System.Windows.Forms.AnchorStyles]::Left 
$dataChart.Series[“Data”].Sort([System.Windows.Forms.DataVisualization.Charting.PointSortOrder]::Descending, “Y”)

$Script:protoChart = New-object System.Windows.Forms.DataVisualization.Charting.Chart 
$protoChart.Width = 700 
$protoChart.Height = 400 
$protoChart.Left = 750 
$protoChart.Top = 30

# create a chartarea to draw on and add to chart 
$protoChartArea = New-Object System.Windows.Forms.DataVisualization.Charting.ChartArea 
$protoChart.ChartAreas.Add($protoChartArea)

# add data to chart 
$tempprotoChartData = $dataCounts
$protoChartData = $protocolCounts
[void]$protoChart.Titles.Add(“Protocols”) 
[void]$protoChart.Series.Add(“Data”) 
$protoChart.Series[“Data”].Points.DataBindXY($protoChartData.Keys, $protoChartData.Values)
#$protoChart.Series[“Data”].Points.DataBindXY($tempprotoChartData.Keys, $tempprotoChartData.Values)
$protoChart.Series[“Data”].ChartType = [System.Windows.Forms.DataVisualization.Charting.SeriesChartType]::Pie
# display the chart on a form 
$protoChart.Anchor = [System.Windows.Forms.AnchorStyles]::Bottom -bor [System.Windows.Forms.AnchorStyles]::Right -bor 
                [System.Windows.Forms.AnchorStyles]::Top -bor [System.Windows.Forms.AnchorStyles]::Left 
$protoChart.Series[“Data”].Sort([System.Windows.Forms.DataVisualization.Charting.PointSortOrder]::Descending, “Y”)
$protoChart.Series[“Data”][“PieLabelStyle”] = “Disabled” 
($protoChart.Series[“Data”].Points.FindMaxByValue())[“Exploded”] = $true
#$protoChart.Series[“Data”][“PieLineColor”] = “Black” 
$legend2 = New-object System.Windows.Forms.DataVisualization.Charting.Legend
$protoChart.Legends.Add($legend2)
$Legend2.Name = "Default"

$Script:servChart = New-object System.Windows.Forms.DataVisualization.Charting.Chart 
$servChart.Width = 700 
$servChart.Height = 400 
$servChart.Left = 750 
$servChart.Top = 440

# create a chartarea to draw on and add to chart 
$servChartArea = New-Object System.Windows.Forms.DataVisualization.Charting.ChartArea 
$servChart.ChartAreas.Add($servChartArea)

# add data to chart 
$tempservChartData = $dataCounts
$servChartData = $serviceCounts
[void]$servChart.Titles.Add(“Services”) 
[void]$servChart.Series.Add(“Data”) 
$servChart.Series[“Data”].Points.DataBindXY($servChartData.Keys, $servChartData.Values)
#$servChart.Series[“Data”].Points.DataBindXY($tempservChartData.Keys, $tempservChartData.Values)
$servChart.Series[“Data”].ChartType = [System.Windows.Forms.DataVisualization.Charting.SeriesChartType]::Pie
# display the chart on a form 
$servChart.Anchor = [System.Windows.Forms.AnchorStyles]::Bottom -bor [System.Windows.Forms.AnchorStyles]::Right -bor 
                [System.Windows.Forms.AnchorStyles]::Top -bor [System.Windows.Forms.AnchorStyles]::Left 
$servChart.Series[“Data”].Sort([System.Windows.Forms.DataVisualization.Charting.PointSortOrder]::Descending, “Y”)
$servChart.Series[“Data”][“PieLabelStyle”] = “Disabled” 
$servChart.Series[“Data”][“Exploded”] = $true
#$servChart.Series[“Data”][“PieLineColor”] = “Black” 
$legend = New-object System.Windows.Forms.DataVisualization.Charting.Legend
$servChart.Legends.Add($legend)
$Legend.Name = "Default"

$Script:timeChart = New-object System.Windows.Forms.DataVisualization.Charting.Chart 
$timeChart.Width = 700 
$timeChart.Height = 400 
$timeChart.Left = 40 
$timeChart.Top = 440

# create a chartarea to draw on and add to chart 
$timeChartArea = New-Object System.Windows.Forms.DataVisualization.Charting.ChartArea 
$timeChart.ChartAreas.Add($timeChartArea)

# add data to chart 
$timeChartData = $($timeData.GetEnumerator() | sort -Property name)
[void]$timeChart.Titles.Add(“Packets over Time”) 
[void]$timeChart.Series.Add(“Data”) 
$timeChartArea.AxisX.Title = “Time” 
$timeChartArea.AxisY.Title = “Packet Counts”
$timeChart.Series[“Data”].Points.DataBindXY($timeChartData.Name, $timeChartData.Value)
#$timeChart.Series[“Data”].Points.DataBindXY($temptimeChartData.Keys, $temptimeChartData.Values)
$timeChart.Series[“Data”].ChartType = [System.Windows.Forms.DataVisualization.Charting.SeriesChartType]::Line
# display the chart on a form 
$timeChart.Anchor = [System.Windows.Forms.AnchorStyles]::Bottom -bor [System.Windows.Forms.AnchorStyles]::Right -bor 
                [System.Windows.Forms.AnchorStyles]::Top -bor [System.Windows.Forms.AnchorStyles]::Left 
#$timeChart.Series[“Data”].Sort([System.Windows.Forms.DataVisualization.Charting.PointSortOrder]::Ascending, “X”)
$timeChart.Series[“Data”][“PieLabelStyle”] = “Disabled” 
$timeChart.Series[“Data”][“Exploded”] = $true
#$timeChart.Series[“Data”][“PieLineColor”] = “Black” 



}
Function displayForm{
    $Form = New-Object Windows.Forms.Form 
    $Form.Text = “PowerShell Network Connection Monitor” 
    $Form.Width = 1500
    $Form.Height = 930 
    $Form.controls.add($dataChart) 
    $Form.controls.add($protoChart) 
    $Form.controls.add($servChart)
    $Form.controls.add($timeChart)  
    $Form.Add_Shown({$Form.Activate()}) 
    $Form.ShowDialog()
}


capturePackets $seconds
 
buildCharts

displayForm