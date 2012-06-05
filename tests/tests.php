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
	}
	function testCredentials () {
		$this->assertNotEmpty($this->url);
		$this->assertNotEmpty($this->password);
		$this->assertNotEmpty($this->username);
	}
	function testConnected () {
		$this->instance = new phRETS($this->url, $this->username, $this->password);
		$this->assertTrue($this->instance->FirewallTest());
	}
}

?>