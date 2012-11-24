<?php
class tests extends PHPUnit_Framework_TestCase {
	public $instance;
	private $url;
	private $password;
	private $username;
	function setUp() {
		//Credentials should be in CSV format of url,password,username
		error_reporting(E_ALL);
		$fh = fopen('credentials.csv', 'r');
		$login = fgetcsv($fh);
		$this->url = $login[0];
		$this->password = $login[1];
		$this->username = $login[2];
		$this->instance = new phRETS($this->url, $this->username, $this->password);
		$this->instance->SetParam('compression_enabled', true);
		$this->instance->SetParam('debug_file', 'test');
		$this->instance->SetParam('debug', true);
		$this->instance->SetParam('force_ua_authentication', true);
		$this->instance->SetParam('disable_follow_location', true);
		$this->instance->SetParam('force_basic_authentication', true);
		$this->instance->SetParam('use_interealty_ua_auth', true);
		$this->instance->SetParam('disable_encoding_fix', true);
		$this->instance->SetParam('override_offset_protection', true);
		$this->instance->SetParam('offset_support', false);
	}
	
	function testConnected() {
		$this->assertTrue($this->instance->is_connected());
	}
	/**
	 * @covers phRETS::getLookupValues
	 */
	function  testgetLookupValues() {
		$this->assertTrue(is_array($this->instance->GetLookupValues('property', 'yesno')));
	}
	function  testGetMetaDataTable() {
		$this->assertTrue(is_array($this->instance->GetMetadataTable('property', '4')));
	}
	function testFirewallTest () {
		$this->assertNotEmpty($this->instance->get_firewall_messages());
		$this->assertTrue($this->instance->test_firewall());
	}
	function  testAuthTypeSupport() {
		$this->assertFalse($this->instance->is_auth_type_supported('digest'));
		$this->assertFalse($this->instance->is_auth_type_supported('basic'));
	}
	/**
	 * @expectedException phRETSException
	 */
	function testInvalidAuthTypeSupport() {
		$this->instance->is_auth_type_supported('unknown');
	}
	/**
	 * @expectedException retsException
	 * @expectedExceptionCode 401
	 */
	function  testFailedLogin () {
		new phRETS($this->url, '1234', '1234');
	}
	function  testGetMetadata() {
		$data = $this->instance->GetMetadata('property', '4');
		$this->assertTrue(is_array($data));
		$this->assertNotEmpty($data);
	}
	function testGetMetaDataTypes() {
		$types = $this->instance->GetMetadataTypes();
		$this->assertTrue(is_array($types));
		$this->assertNotEmpty($types);
	}
	function  testgetMetaDataObjects() {
		$objects = $this->instance->GetMetadataObjects('property');
		$this->assertTrue(is_array($objects));
		$this->assertNotEmpty($objects);
	}
	/**
	 * @expectedException retsException
	 */
	function  testSetUnknownParam() {
		$this->instance->SetParam('unknowmn', false);
	}
	
	function  testFreeResult() {
		$this->assertFalse($this->instance->getLastSearchId());
		$this->instance->Search('property', '4', $this->instance->PrepareQuery(array('176'=>'100000-120000')), array('Limit'=>1, 'Select'=>176));
		$this->assertTrue($this->instance->FreeResult($this->instance->getLastSearchId()));
		$this->assertFalse($this->instance->FreeResult(99));
	}
	/**
	 * test success on good search
	 */
	function  testGoodSearchQuery() {
		$search_id = $this->instance->SearchQuery("property", '4', $this->instance->PrepareQuery(array('176'=>'100000-120000')), array('Limit'=>1, 'Select'=>176));
		$this->assertTrue(is_numeric($search_id));
		$this->assertTrue(is_numeric($this->instance->getTotalRecordsFound()));
		$this->assertTrue(is_numeric($this->instance->getNumRows()));
		$this->assertTrue($this->instance->IsMaxrowsReached());
		$this->assertTrue(is_array($this->instance->SearchGetFields($search_id)));
	}
	/**
	 * make sure that search related functions return false
	 * when there is no search data
	 */
	function  testFalseOnNoSearch() {
		$this->assertFalse($this->instance->FetchRow(99));
		$this->assertFalse($this->instance->getTotalRecordsFound());
		$this->assertFalse($this->instance->getNumRows());
		$this->assertFalse($this->instance->IsMaxrowsReached());
		$this->assertFalse($this->instance->SearchGetFields(null));
		$this->assertFalse($this->instance->SearchGetFields(1));
	}
	function testIsServerVersion() {
		$this->assertTrue($this->instance->is_server_version('1_5_or_below'));
	}
	/**
	 * test no results
	 * @expectedException retsException
	 * @expectedExceptionCode 20201
	 */
	function  testSearchWithNoResults() {
		$search_id = $this->instance->Search('property', '4', '(176=9999999999999+)');
		$this->assertTrue( 0 ===  $this->instance->getTotalRecordsFound());
		$this->assertTrue( 0 === $this->instance->getNumRows());
		$this->assertFalse($this->instance->IsMaxrowsReached());
	}
	function testCredentials () {
		$this->assertNotEmpty($this->url, 'No URL found. credentials.csv should contain url,password,username');
		$this->assertStringStartsWith('http', $this->url, 'Invalid RETS URL');
		$this->assertNotEmpty($this->password);
		$this->assertNotEmpty($this->username);
	}
	function testUAandQuery () {
		$this->assertInstanceOf('phRETS',
				new phRETS($this->url.'?query=string', $this->username, $this->password, '3453125')
		);
	}
	function testCapabilityChecker() {
		$this->assertTrue($this->instance->test_requirements_met());
		$this->assertArrayHasKey('simplexml_load_string', $this->instance->get_test_requirements());
		$this->assertArrayHasKey('curl_init', $this->instance->get_test_requirements());
	}
	function testSearchQueryPrepare() {
		$query = array('178'=>'ACT');
		$prepared_query = $this->instance->PrepareQuery($query);
		$this->assertStringStartsWith('(', $prepared_query);
		$this->assertStringEndsWith(')', $prepared_query);
	}
	function  testGetObject() {
		$search = $this->instance->Search('property', '4', $this->instance->PrepareQuery(array('176'=>'100000-120000')), array('Limit'=>2, 'Select'=>'sysid'));
		$sysid = $search[0]['sysid'];
		//default implementation
		$obj = $this->instance->GetObject('property', 'photo', $sysid);
		$this->assertTrue(is_array($obj));
		//get 1 photo
		$single = $this->instance->GetObject('property', 'photo', $sysid, 1);
		$this->assertTrue(is_array($single));
		$this->assertTrue($single[0]['Success']);
		//get multiple photos by csv
		$select = $this->instance->GetObject('property', 'photo', $sysid, '1,2,3');
		$this->assertTrue(is_array($select));
		$this->assertTrue($select[0]['Success']);
		//get multiple properties
		$multiple_ids = $sysid.','.$search[1]['sysid'];
		$properties = $this->instance->GetObject('property', 'photo', $multiple_ids);
	}
	function  testGetAllLookupValues() {
		$this->assertTrue(is_array($this->instance->GetAllLookupValues('property')));
	}
	/**
	 * @covers phRETS::getMetadataResources()
	 */
	function testGetMetaResources () {
		$resources = $this->instance->GetMetadataResources();
		$this->assertTrue(is_array($resources));
		$this->assertNotEmpty($resources);
	}
	function  testGetMetaDataClasses() {
		$property_meta = $this->instance->GetMetadataClasses("property");
		$this->assertTrue(is_array($property_meta));
		$this->assertNotEmpty($property_meta);
	}
	function  testgetMetaDataInfo() {
		$info = $this->instance->GetMetadataInfo();
		$this->assertNotEmpty($info);
	}
	function  testGetServerInfo() {
		$info = $this->instance->GetServerInformation();
		$this->assertArrayHasKey('SystemID', $info);
		$this->assertArrayHasKey('Comments', $info);
		$software = $this->instance->GetServerSoftware();
	}
	function  testDisconnect() {
		$this->assertTrue($this->instance->Disconnect());
	}
	function testNotConnected() {
		$this->assertFalse($this->instance->is_connected());
	}
}

?>