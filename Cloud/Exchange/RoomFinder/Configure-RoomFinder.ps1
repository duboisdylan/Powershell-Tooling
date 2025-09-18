#New-DistributionGroup -Name “FAC Rooms” -RoomList
#Set-DistributionGroup -Identity “West Coast Office” -RoomList
#Set-DistributionGroup -Identity “East Coast Office” -RoomList

#New-DistributionGroup -Name “East Coast Office” -OrganizationalUnit “domain1.local/Test” -RoomList
#Get-DistributionGroup | ft -auto Name, RecipientType, RecipientTypeDetails
#Add-DistributionGroupMember -Identity “FAC” -Member ConfRoomA@domainname.com
#Get-DistributionGroupMember -Identity “FAC”

#New-DistributionGroup -Name “DA Rooms” -RoomList

Connect-ExchangeOnline -ShowBanner:$false

Get-DistributionGroup -RoomList 

Get-DistributionGroup -ResultSize Unlimited | ? {$_.RecipientTypeDetails -eq "RoomList"} | Format-Table DisplayName,Identity,PrimarySmtpAddress –AutoSize