<?php
class tests extends PHPUnit_Framework_TestCase {
	public $instance;
	private $url;
	private $password;
	private $username;
	function setUp() {
		//Credentials should be in CSV format of url,password,username
// 		error_reporting(E_ALL);
		$fh = fopen('credentials.csv', 'r');
		$login = fgetcsv($fh);
		$this->url = $login[0];
		$this->password = $login[1];
		$this->username = $login[2];
		$this->instance = new phRETS($this->url, $this->username, $this->password);
		$this->instance->SetParam('compression_enabled', true);
		$this->instance->SetParam('debug', true);
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
	function testNotConnected() {
		$this->markTestIncomplete();
		$this->assertFalse($this->instance->is_connected());
	}
	function testConnect() {
		$this->markTestIncomplete();
		$this->assertTrue($this->instance->connect());
	}
	function testConnected() {
		$this->markTestIncomplete();
		$this->instance->connect();
		$this->assertTrue($this->instance->is_connected());
	}
	function  testFreeResult() {
		$this->instance->FreeResult(1);
	}
	function  testDisconnect() {
		$this->assertTrue($this->instance->Disconnect());
	}
}

?>