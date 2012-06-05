<?php 
class tests extends PHPUnit_Framework_TestCase {
	public $instance;
	private $url;
	private $password;
	private $username;
	function setUp() {
		//Credentials should be in CSV format of url,password,username
		$fh = fopen('credentials.csv', 'r');
		$login = fgetcsv($fh);
		$this->url = $login[0];
		$this->password = $login[1];
		$this->username = $login[2];
		$this->instance = new phRETS($this->url, $this->username, $this->password);
	}
	function testCredentials () {
		$this->assertNotEmpty($this->url);
		$this->assertNotEmpty($this->password);
		$this->assertNotEmpty($this->username);
	}
	function testConnected () {
		$this->assertFalse($this->instance->Error());
	}
	function testSearchQueryPrepare() {
		$query = array('178'=>'ACT');
		$prepared_query = $this->instance->PrepareQuery($query);
		$this->assertStringStartsWith('(', $prepared_query);
		$this->assertStringEndsWith(')', $prepared_query);
	}
	function testFirewall () {
		$this->assertTrue($this->instance->FirewallTest());
	}
	function testGetMetaResources () {
		$resources = $this->instance->GetMetadataResources();
		$this->assertNotEmpty($resources);
		$this->assertTrue(is_array($resources));
	}
}

?>