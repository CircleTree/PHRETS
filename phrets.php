<?php

/**
*  PHRETS - PHP library for RETS
*  Copyright 2012 Circle Tree, LLC.
*  Based on:
*	  	http://troda.com/projects/phrets/
*  		Copyright (C) 2007-2011 Troy Davisson
*
*  This library is divided into 2 sections: high level and low level
*    High level: Helpful functions that take much of the burden out of processing RETS data
*    Low level: Framework for communicating with a RETS server.  High level functions sit on top of these
*
*/
/**
 * Parent Class Exception
 */
class phRETSExceptionsClass extends Exception {
	function  __construct ($message, $code = null) {
		parent::__construct($message, $code);
	}
}
/**
 * runtime / configuration exceptions 
 */
class phRETSException extends Exception {
}
/**
 * Server exceptions
 */
class retsException extends Exception {
	
}
class retsXMLParsingException extends Exception {
	
}

if (! class_exists("phRETS")) :
class phRETS {
	private $service_urls = array();
	private $curl_handle = false;
	private $server_hostname;
	private $server_port;
	private $server_protocol;
	private $server_version;
	private $server_software;
	private $search_data;
	private $static_headers = array();
	private $server_information = array();
	private $cookie_file = "";
	private $debug_file = "rets_debug.txt";
	private $debug_file_handle = false;
	private $debug_mode = FALSE;
	private $allowed_capabilities = array(
			"Action" => 1,
			"ChangePassword" => 1,
			"GetObject" => 1,
			"Login" => 1,
			"LoginComplete" => 1,
			"Logout" => 1,
			"Search" => 1,
			"GetMetadata" => 1,
			"ServerInformation" => 1,
			"Update" => 1,
			"PostObject" => 1,
			"GetPayloadList" => 1
			);
	private $last_request = array();
	private $auth_support_basic = false;
	private $auth_support_digest = false;
	private $last_response_headers = array();
	private $last_response_body = "";
	private $last_response_headers_raw = "";
	private $last_remembered_header = "";
	private $compression_enabled = false;
	private $ua_pwd = "";
	private $ua_auth = false;
	private $request_id = "";
	private $disable_follow_location = false;
	private $force_basic_authentication = false;
	private $use_interealty_ua_auth = false;
	private $int_result_pointer = 0;
	private $last_request_url;
	private $session_id;
	private $catch_last_response = false;
	private $disable_encoding_fix = false;
	private $offset_support = false;
	private $override_offset_protection = false;
	private $is_connected = false;
	/**
	 * Stores messages regarding firewall test results
	 * @var array
	 */
	private $firewall_messages = array();
	//login
	private $username;
	private $password;
	private $login_url;
	private $xml;
	/**
	 * required php modules / capabilites
	 * @var array
	 */
	private static $test_requirements = array('curl_init' , 'simplexml_load_string');
	
	public function is_connected() {
		return $this->is_connected;
	}
	/**
	 * connect to the remote server, and log in 
	 */
	public function __construct($login_url, $username, $password, $ua_pwd = "") {
	
		$this->username = $username;
		$this->password = $password;
		
	
		// chop up Login URL to use for later requests
		$url_parts = parse_url($login_url);
		$this->server_hostname = $url_parts['host'];
		$this->server_port = ( empty($url_parts['port']) ) ? 80 : $url_parts['port'];
		$this->server_protocol = $url_parts['scheme'];
	
		$this->service_urls['Login'] = $url_parts['path'];

		
		if (empty($this->static_headers['RETS-Version'])) {
			$this->AddHeader("RETS-Version", "RETS/1.5");
		}
		if (empty($this->static_headers['User-Agent'])) {
			$this->AddHeader("User-Agent", "PHRETS/1.0");
		}
		if (empty($this->static_headers['Accept']) && $this->static_headers['RETS-Version'] == "RETS/1.5") {
			$this->AddHeader("Accept", "*/*");
		}
		
		//Append query parms if set
		if (isset($url_parts['query']) && ! empty($url_parts['query']) ) {
			$this->service_urls['Login'] .= "?{$url_parts['query']}";
		}
		if (! empty($ua_pwd) ) {
			// force use of RETS 1.7 User-Agent Authentication
			$this->ua_auth = true;
			$this->ua_pwd = $ua_pwd;
		}
	
	
	
		if (empty($this->cookie_file)) {
			$this->cookie_file = tempnam("", "phrets");
		}
	
		if (!is_writable($this->cookie_file)) {
			throw new phRETSException("Cookie file \"{$this->cookie_file}\" cannot be written to.  
			Must be an absolute path and must be writable");
		}
		@touch($this->cookie_file);
		
		$this->initialize_curl();
		// make request to Login transaction
		
		$this->RETSRequest($this->service_urls['Login']);
		$this->ParseXMLResponse($this->last_response_body);
		$this->save_last_request();
		
		// chop up login response
		// if multiple parts of the login response aren't found splitting on \r\n, redo using just \n
		$login_response = array();
		
		if ($this->is_server_version('1_0')) {
			//@codeCoverageIgnoreStart
			//@todo test on rets 1.0 
			if (isset($this->xml)) {
			$login_response = explode("\r\n", $this->xml);
				if (empty($login_response[3])) {
					$login_response = explode("\n", $this->xml);
				}
			}
		} else {
			//@codeCoverageIgnoreEnd
			if (isset($this->xml->{'RETS-RESPONSE'})) {
				$login_response = explode("\r\n", $this->xml->{'RETS-RESPONSE'});
				if (empty($login_response[3])) {
				$login_response = explode("\n", $this->xml->{'RETS-RESPONSE'});
				}
			}
		}
		
		// parse login response.  grab all capability URLs known and ones that begin with X-
		// otherwise, it's a piece of server information to save for reference
		foreach ($login_response as $line) {
			$name = $value = null;
		
			if (strpos($line, '=') !== false) {
				@list($name,$value) = explode("=", $line, 2);
			}
			
			$name = trim($name);
			$value = trim($value);
			if (!empty($name) && !empty($value)) {
				if (isset($this->allowed_capabilities[$name]) || preg_match('/^X\-/', $name) == true) {
					$this->service_urls[$name] = $value;
				} else {
					$this->server_information[$name] = $value;
				}
			}
		}
		
		// if 'Action' capability URL is provided, we MUST request it following the successful Login
		if (isset($this->service_urls['Action']) && !empty($this->service_urls['Action'])) {
			$this->RETSRequest($this->service_urls['Action']);
		}
		
		if ($this->last_request['ReplyCode'] == 0) {
			$this->is_connected = true;
			return true;
		} else {
			throw new retsException($this->last_request['ReplyText'], $this->last_request['ReplyCode']);
		}
	
	}
	/**
	 * initialize $this->curl_handle
	 */
	private function initialize_curl() {
		//check if cURL is already initialized
		if (is_resource($this->curl_handle)) 
			return;
		//Initialize
		$this->curl_handle = curl_init();
		$curl_options = array(
				CURLOPT_SSL_VERIFYPEER => false,
				CURLOPT_SSL_VERIFYHOST => false,
				CURLOPT_HEADER => false,
				CURLOPT_TIMEOUT => 0,
				CURLOPT_COOKIEFILE => $this->cookie_file,
				CURLOPT_RETURNTRANSFER => true,
				CURLOPT_USERPWD => $this->username.":".$this->password,
				CURLOPT_HEADERFUNCTION => array( $this, 'read_custom_curl_headers'),
		);
		if ($this->disable_follow_location != true || $this->compression_enabled == true)
			array_push($curl_options, array(CURLOPT_ENCODING => "gzip"));
		if ($this->disable_follow_location != true)
			array_push($curl_options, array(CURLOPT_FOLLOWLOCATION => 1));
		if ($this->force_basic_authentication == true)
			array_push($curl_options, array(CURLOPT_HTTPAUTH => CURLAUTH_BASIC));
		else
			array_push($curl_options, array(CURLOPT_HTTPAUTH => CURLAUTH_DIGEST|CURLAUTH_BASIC));
		
		if ($this->debug_mode == true) {
			$this->debug_file_handle = @fopen($this->debug_file, 'a');
			if (is_resource( $this->debug_file_handle) ) {
				array_push($curl_options, array(CURLOPT_VERBOSE => true ));
				array_push($curl_options, array(CURLOPT_STDERR => $this->debug_file ));
			} else {
				throw new retsException("Unable to save debug log to {$this->debug_file}");
			}
		}
		curl_setopt_array($this->curl_handle, $curl_options);
	}

	/**
	 * @codeCoverageIgnore
	 * @deprecated use test_firewall
	 */
	public function FirewallTest() {
		trigger_error(__METHOD__ . ' is Deprecated. Use phRETS::test_firewall()', E_USER_DEPRECATED);
		$this->test_firewall();
	}
	/**
	 * Tests internet connectivity
	 * @return bool true on success, false on failure
	 */
	public function test_firewall () {
		$google = $this->do_firewall_test_connection("http://www.google.com/");
		$crt80 = $this->do_firewall_test_connection("http://demo.crt.realtors.org/");
		$dis6103 = $this->do_firewall_test_connection("http://dis.com:6103/rets/");
		$flexmls80 = $this->do_firewall_test_connection("http://retsgw.flexmls.com/");
		$flexmls6103 = $this->do_firewall_test_connection("http://retsgw.flexmls.com:6103/");
		
		//we ignore the polymorphisms here because they are too difficult to test
		//@codeCoverageIgnoreStart
		if (!$google && !$crt80 && !$dis6103 && !$flexmls80 && !$flexmls6103) {
			$msg = "Firewall Result: All tests failed.  Possible causes:";
			$msg .= "<ol>";
			$msg .= "<li>Firewall is blocking your outbound connections</li>";
			$msg .= "<li>You aren't connected to the internet</li>";
			$msg .= "</ol>";
			array_unshift($this->firewall_messages, $msg);
			return false;
		}
		
		if (!$dis6103 && !$flexmls6103) {
			$msg = "Firewall Result: All port 6103 tests failed.  ";
			$msg .= "Likely cause: Firewall is blocking your outbound connections on port 6103.";
			array_unshift($this->firewall_messages, $msg);
			return false;
		}
		
		if ($google && $dis6103 && $crt80 && $flexmls6103 && $flexmls80) {
			$msg = "Firewall Result: All tests passed.";
			array_unshift($this->firewall_messages, $msg);
			return true;
		}
		
		if (($dis6103 && !$flexmls6103) || (!$dis6103 && $flexmls6103)) {
			$msg = "Firewall Result: At least one port 6103 test passed.  ";
			$msg .= "Likely cause: One of the test servers might be down but connections on port 80 and port 6103 should work.";
			array_unshift($this->firewall_messages, $msg);
			return true;
		}
		
		if (!$google || !$crt80 || !$flexmls80) {
			$msg = "Firewall Result: At least one port 80 test failed.  ";
			$msg .= "Likely cause: One of the test servers might be down.";
			array_unshift($this->firewall_messages, $msg);
			return true;
		}
		
		$msg = "Firewall Test Failure: Unable to guess the issue.";
		array_unshift($this->firewall_messages, $msg);
		return false;
		//@codeCoverageIgnoreEnd
	}
	private static function test_required_capabilities() {
		$return = array();		
		foreach (self::$test_requirements as $requirement) {
			if ( function_exists($requirement) ) {
				$return[ $requirement ] = true;
			} else {
				$return[ $requirement ] = false;
			}
		}
		return $return;
	}
	/**
	 * @return bool true if met, false if not.
	 * use get_test_requirements to see failed
	 */
	public static function test_requirements_met () {
		if (false === array_search(false, self::test_required_capabilities())) {
			return true;
		} else {
			//@codeCoverageIgnoreStart
			return false;
			//@codeCoverageIgnoreEnd
		}
	}
	/**
	 * gets test statuses
	 * @return array function name => true/false
	 */
	public static function get_test_requirements () {
		return self::test_required_capabilities();
	}
	/**
	 * gets firewall messages, running a test if the messages array is empty
	 * @return array messages of successes  / failures
	 */
	public function get_firewall_messages() {
		if ( 0 === count($this->firewall_messages) ) {
			$this->test_firewall();
		}
		return $this->firewall_messages;
	}
	private function do_firewall_test_connection($hostname) {
		curl_setopt($this->curl_handle, CURLOPT_URL, $hostname);
		curl_exec($this->curl_handle);
		$response_code = curl_getinfo($this->curl_handle, CURLINFO_HTTP_CODE);
		if ($response_code == 200 || $response_code == 304 || $response_code == 403) {
			$this->firewall_messages[] = "Firewall Test: {$hostname} GOOD";
			return true;
		} else {
			$this->firewall_messages[] = "Firewall Test: {$hostname} FAILED. HTTP Status Code: ".$response_code;
			return false;
		}

	}

/**
 * Get RETS Objects (typically photos)
 * @param string $resource RETS Resource for requested object
 * @param string $type RETS GetObject type. See GetMetadataObjects for available types.
 * @param mixed $id ID of Object. This is the value of the KeyName field within the Resource for your record (typically the MLS#). This is NOT the full ID as described in the RETS specification.
 * @param int $photo_number Optional. Requested object ID. Typically represents the photo order. Possible Values: 0, 1, 2, 3, etc., or * (asterisk) to request all objects. Default is *
 * @param bool $location Optional. Used to return URLs rather than image data. Not always supported by the server. True gets URLs, False gets binary image data. Default is False.
 * @return boolean|multitype:boolean multitype:string boolean unknown
 */
	public function GetObject($resource, $type, $id, $photo_number = '*', $location = FALSE) {
		
		$return_photos = array();


		$send_id = "";
		$send_numb = "";

		// check if $photo_number needs fixing
		if (strpos($photo_number, ',') !== false) {
			// change the commas to colons for the request
			$photo_number = preg_replace('/\,/', ':', $photo_number);
		}

		if (strpos($photo_number, ':') !== false) {
			// photo number contains multiple objects
			// chopping and cleaning
			$requested_numbers = explode(":", $photo_number);
			if (is_array($requested_numbers)) {
				foreach ($requested_numbers as $numb) {
					$numb = trim($numb);
					if (!empty($numb) || $numb == "0") {
					$send_numb .= "{$numb}:";
					}
				}
			}
			$send_numb = preg_replace('/\:$/', '', $send_numb);
		}
		else {
			$send_numb = trim($photo_number);
		}
		if (strpos($id, ',') !== false) {
			// id contains multiple objects.
			// chopping and combining with photo_number
			$requested_ids = explode(",", $id);
			if (is_array($requested_ids)) {
				foreach ($requested_ids as $req_id) {
				$req_id = trim($req_id);
					if (!empty($req_id) && $req_id != "0") {
						$send_id .= "{$req_id}:{$send_numb},";
					}
				}
			}
			$send_id = preg_replace('/\,$/', '', $send_id);
		} else {
			$send_id = trim($id).':'.$send_numb;
		}
		// make request
		$location_int = $location ? 1 : 0; 
		$result = $this->RETSRequest($this->service_urls['GetObject'],
						array(
								'Resource' => $resource,
								'Type' => $type,
								'ID' => $send_id,
								'Location' => $location_int
								)
						);

		// fix case issue if exists
		if (isset($this->last_response_headers['Content-type']) && !isset($this->last_response_headers['Content-Type'])) {
			$this->last_response_headers['Content-Type'] = $this->last_response_headers['Content-type'];
		}

		if (!isset($this->last_response_headers['Content-Type'])) {
			$this->last_response_headers['Content-Type'] = "";
		}

		// check what type of response came back
		if (strpos($this->last_response_headers['Content-Type'], 'multipart') !== false) {

			// help bad responses be more multipart compliant
			$this->last_response_body = "\r\n{$this->last_response_body}\r\n";

			// multipart
			preg_match('/boundary\=\"(.*?)\"/', $this->last_response_headers['Content-Type'], $matches);
			if (isset($matches[1])) {
				$boundary = $matches[1];
			} else {
				preg_match('/boundary\=(.*?)(\s|$|\;)/', $this->last_response_headers['Content-Type'], $matches);
				$boundary = $matches[1];
			}
			// strip quotes off of the boundary
			$boundary = preg_replace('/^\"(.*?)\"$/', '\1', $boundary);

			// clean up the body to remove a reamble and epilogue
			$this->last_response_body = preg_replace('/^(.*?)\r\n--'.$boundary.'\r\n/', "\r\n--{$boundary}\r\n", $this->last_response_body);
			// make the last one look like the rest for easier parsing
			$this->last_response_body = preg_replace('/\r\n--'.$boundary.'--/', "\r\n--{$boundary}\r\n", $this->last_response_body);

			// cut up the message
			$multi_parts = array();
			$multi_parts = explode("\r\n--{$boundary}\r\n", $this->last_response_body);
			// take off anything that happens before the first boundary (the preamble)
			array_shift($multi_parts);
			// take off anything after the last boundary (the epilogue)
			array_pop($multi_parts);

			// go through each part of the multipart message
			foreach ($multi_parts as $part) {
				// default to processing headers
				$on_headers = true;
				$on_body = false;
				$first_body_found = false;
				$this_photo = array();

				// go through the multipart chunk line-by-line
				$body_parts = array();
				$body_parts = explode("\r\n", $part);
				$this_photo['Data'] = "";
				foreach ($body_parts as $line) {
					if (empty($line) && $on_headers == true) {
						// blank line.  switching to processing a body and moving on
						$on_headers = false;
						$on_body = true;
						continue;
					}
					if ($on_headers == true) {
						// non blank line and we're processing headers so save the header
						$header = null;
						$value = null;

						if (strpos($line, ':') !== false) {
							@list($header, $value) = explode(':', $line, 2);
						}

						$header = trim($header);
						$value = trim($value);
						if (!empty($header)) {
							if ($header == "Description") {
								// for servers where the implementors didn't read the next word in the RETS spec.
								// 'Description' is the BNF term. Content-Description is the correct header.
								// fixing for sanity
								$header = "Content-Description";
							}
							// fix case issue if exists
							if ($header == "Content-type") {
								$header = "Content-Type";
							}
							$this_photo[$header] = $value;
						}
					}
					if ($on_body == true) {
						if ($first_body_found == true) {
							// here again because a linebreak in the body section which was cut out in the explode
							// add the CRLF back
							$this_photo['Data'] .= "\r\n";
						}
						// non blank line and we're processing a body so save the line as part of Data
						$first_body_found = true;
						$this_photo['Data'] .= $line;
					}
				}
				// done with parsing out the multipart response
				// check for errors and finish up

				$this_photo['Success'] = true; // assuming for now

				if (strpos($this_photo['Content-Type'], 'xml') !== false) {
					// this multipart might include a RETS error
					$this->ParseXMLResponse($this_photo['Data']);

					if ($this->xml['ReplyCode'] == 0 || empty($this_photo['Data'])) {
						// success but no body
						$this_photo['Success'] = true;
					} else {
						// RETS error in this multipart section
						$this_photo['Success'] = false;
						$this_photo['ReplyCode'] = "{$this->xml['ReplyCode']}";
						$this_photo['ReplyText'] = "{$this->xml['ReplyText']}";
					}
				}

				// add information about this multipart to the returned array
				$return_photos[] = $this_photo;
			}
		} else {
			// all we know is that the response wasn't a multipart so it's either a single photo or error
			$this_photo = array();

			$this_photo['Success'] = true; // assuming for now
			if (isset($this->last_response_headers['Content-ID'])) {
				$this_photo['Content-ID'] = $this->last_response_headers['Content-ID'];
			}
			if (isset($this->last_response_headers['Object-ID'])) {
				$this_photo['Object-ID'] = $this->last_response_headers['Object-ID'];
			}
			if (isset($this->last_response_headers['Content-Type'])) {
				$this_photo['Content-Type'] = $this->last_response_headers['Content-Type'];
			}
			if (isset($this->last_response_headers['MIME-Version'])) {
				$this_photo['MIME-Version'] = $this->last_response_headers['MIME-Version'];
			}
			if (isset($this->last_response_headers['Location'])) {
				$this_photo['Location'] = $this->last_response_headers['Location'];
			}
			if (isset($this->last_response_headers['Preferred'])) {
				$this_photo['Preferred'] = $this->last_response_headers['Preferred'];
			}

			if (isset($this->last_response_headers['Description'])) {
				if (!empty($this->last_response_headers['Description'])) {
					// for servers where the implementors didn't read the next word in the RETS spec.
					// 'Description' is the BNF term. Content-Description is the correct header.
					// fixing for sanity
					$this_photo['Content-Description'] = $this->last_response_headers['Description'];
				}
			}
			if (isset($this->last_response_headers['Content-Description'])) {
				$this_photo['Content-Description'] = $this->last_response_headers['Content-Description'];
			}

			$this_photo['Length'] = strlen($this->last_response_body);
			$this_photo['Data'] = $this->last_response_body;

			if (isset($this->last_response_headers['Content-Type'])) {
				if (strpos($this->last_response_headers['Content-Type'], 'xml') !== false) {
					// RETS error maybe?
					$this->ParseXMLResponse($this->last_response_body);

					if ($this->xml['ReplyCode'] == 0 || empty($body)) {
						// false alarm.  we're good
						$this_photo['Success'] = true;
					} else {
						// yes, RETS error
						$this_photo['ReplyCode'] = "{$this->xml['ReplyCode']}";
						$this_photo['ReplyText'] = "{$this->xml['ReplyText']}";
						$this_photo['Success'] = false;
					}
				}
			}

			// add information about this photo to the returned array
			$return_photos[] = $this_photo;
		}

		// return everything
		return $return_photos;
	}

	/**
	 * does the response contain a maxrows element?
	 * @see Rets 1.7.2::7.4.3 Limit
	 * @param bool true if there are more rows
	 */
	public function IsMaxrowsReached($pointer_id = "") {
		if (empty($pointer_id)) {
			$pointer_id = $this->int_result_pointer;
		}
		if (isset($this->search_data)) {
			return $this->search_data[$pointer_id]['maxrows_reached'];
		} else {
			return false;
		}
	}

	/**
	 * gets the total number of records returned by the last search
	 * @param unknown_type $pointer_id
	 */
	public function getTotalRecordsFound($pointer_id = "") {
		if (empty($pointer_id)) {
			$pointer_id = $this->int_result_pointer;
		}
		if ( isset( $this->search_data )) {
			return $this->search_data[$pointer_id]['total_records_found'];
		} else {
			return false;
		}
	}

	/**
	 * gets the number of results returned by the last search
	 * @param int $pointer_id 
	 * 
	 */
	public function getNumRows($pointer_id = "") {
		if (empty($pointer_id)) {
			$pointer_id = $this->int_result_pointer;
		}
		if (isset($this->search_data)) {
			return $this->search_data[$pointer_id]['last_search_returned'];
		} else {
			return false;
		}
	}

	public function SearchGetFields($pointer_id) {
		if (! empty($pointer_id) ) {
			if (isset($this->search_data[ $pointer_id ])) {
				return $this->search_data[$pointer_id]['column_names'];
			} else {
				return false;
			}			
		} else {
			return false;
		}
	}
	

	
	public function FreeResult($pointer_id) {
		if (!empty($pointer_id) && isset($this->search_data[$pointer_id])) {
			unset($this->search_data[$pointer_id]['data']);
			unset($this->search_data[$pointer_id]['delimiter_character']);
			unset($this->search_data[$pointer_id]['column_names']);
			return true;
		} else {
			return false;
		}
	}


	public function FetchRow($pointer_id) {
		if (empty($pointer_id) || (! isset( $this->search_data[$pointer_id] ))) {
			return false;
		}
		$this_row = false;
		if (isset($this->search_data[$pointer_id]['data'])) {
			$field_data = current($this->search_data[$pointer_id]['data']);
			next($this->search_data[$pointer_id]['data']);
		}

		if ( !empty($field_data) ) {
			$this_row = array();

			// split up DATA row on delimiter found earlier
			$field_data = preg_replace("/^{$this->search_data[$pointer_id]['delimiter_character']}/", "", $field_data);
			$field_data = preg_replace("/{$this->search_data[$pointer_id]['delimiter_character']}\$/", "", $field_data);
			$field_data = explode($this->search_data[$pointer_id]['delimiter_character'], $field_data);

			foreach ($this->search_data[$pointer_id]['column_names'] as $key => $name) {
				// assign each value to it's name retrieved in the COLUMNS earlier
				$this_row[$name] = $field_data[$key];
			}
		}
		return $this_row;
	}
	
	/**
	 * 
	 * @param array $query key value pairs to search
	 * @return string $query_string DMQL formatted query
	 */
	public function PrepareQuery(array $query) {
		$query_string = "";		
		foreach ($query as $id=>$val) {
			$query_string .= "($id=$val),";
		}		
		return rtrim($query_string, ',');
	}

	/**
	 * @param string $resource RETS resource (Property,Agent, etc.)
	 * @param string $class RETS class id to query
	 * @param string $query DMQL query string
	 * @param array $optional_params array of RETS
	 * @return int internal result pointer ID 
	 * @todo update $query param to being optional with rets 1.8.0
	 */
	public function SearchQuery($resource, $class, $query, $optional_params = array()) {

		//increment results pointer
		$this->int_result_pointer++;
		$this->search_data[$this->int_result_pointer]['last_search_returned'] = 0;
		$this->search_data[$this->int_result_pointer]['total_records_found'] = 0;
		$this->search_data[$this->int_result_pointer]['column_names'] = "";
		$this->search_data[$this->int_result_pointer]['delimiter_character'] = "";
		$this->search_data[$this->int_result_pointer]['search_requests'] = 0;

		// setup default request arguments
		$default_arguments = array(
				'QueryType' => "DMQL2",
				'SearchType' => $resource,
				'Class' => $class,
				'Count' => 1,
				'Format' => "COMPACT-DECODED",
				'Limit' => 99999999,
				'StandardNames' => 0,
				'Select' => null,
				'RestrictedIndicator' => '*************'
			);
		// setup additional, optional request arguments
		$search_arguments = array_merge($default_arguments, $optional_params);
		if ($query == "*" || preg_match('/^\((.*)\)$/', $query)) {
			// check if the query passed is missing the outer parenthesis
			$search_arguments['Query'] = $query;
		} else {
			// if so, add them
			$search_arguments['Query'] = '('.$query.')';
		}

		if (isset($optional_params['Offset'])) {
			$search_arguments['Offset'] = $optional_params['Offset'];
		} elseif ($this->offset_support && empty($optional_params['Offset'])) {
			// start auto-offset looping with Offset at 1
			$search_arguments['Offset'] = 1;
		}

		// Keep searching if MAX ROWS is reached and offset_support is true
		$continue_searching = true; 
		while ($continue_searching) {

			$this->search_data[$this->int_result_pointer]['maxrows_reached'] = false;
			$this->search_data[$this->int_result_pointer]['search_requests']++;

			if ($this->search_data[$this->int_result_pointer]['search_requests'] == 300 && !$this->override_offset_protection) {
				// this call for SearchQuery() has resulted in X number of search requests
				// which is considered excessive.  stopping the process in order to prevent
				// abuse against the server.  almost ALWAYS happens when the user thinks Offset
				// is supported by the server when it's actually NOT supported
				throw phRETSException("Last SearchQuery() has resulted in 300+ requests to the server.  Stopping to prevent abuse");
			}

			// make request
			$this->RETSRequest($this->service_urls['Search'], $search_arguments);
			$body = $this->fix_encoding($this->last_response_body);

			$this->ParseXMLResponse($body);
			$this->save_last_request();
			// log replycode and replytext for reference later
			

			if (isset($this->xml->DELIMITER)) {
				// delimiter found so we have at least a COLUMNS row to parse
				$delimiter_character = chr("{$this->xml->DELIMITER->attributes()->value}");
				$this->search_data[$this->int_result_pointer]['delimiter_character'] = $delimiter_character;
				$column_names = "{$this->xml->COLUMNS[0]}";
				$column_names = preg_replace("/^{$delimiter_character}/", "", $column_names);
				$column_names = preg_replace("/{$delimiter_character}\$/", "", $column_names);
				$this->search_data[$this->int_result_pointer]['column_names'] = explode($delimiter_character, $column_names);
			}

			if (isset($this->xml->DATA)) {
				foreach ($this->xml->DATA as $key) {
					$field_data = "{$key}";
					// split up DATA row on delimiter found earlier
					$this->search_data[$this->int_result_pointer]['data'][] = $field_data;
					$this->search_data[$this->int_result_pointer]['last_search_returned']++;
				}
			}

			if (isset($this->xml->MAXROWS)) {
				// MAXROWS tag found.  the RETS server withheld records.
				// if the server supports Offset, more requests can be sent to page through results
				// until this tag isn't found anymore.
				$this->search_data[$this->int_result_pointer]['maxrows_reached'] = true;
			}

			if (isset($this->xml->COUNT)) {
				// found the record count returned.  save it
				$this->search_data[$this->int_result_pointer]['total_records_found'] = "{$this->xml->COUNT->attributes()->Records}";
			}

			if ($this->IsMaxrowsReached($this->int_result_pointer) && $this->offset_support) {
				$continue_searching = true;
				$search_arguments['Offset'] = $this->NumRows($this->int_result_pointer) + 1;
			} else {
				$continue_searching = false;
			}
		}

		return $this->int_result_pointer;
	}
	
	/**
	 * Returns data datatable of results
	 * @see phRETS::SearchQuery()
	 * @return array $data[] = row
	 */

	public function Search($resource, $class, $query = "", $optional_params = array()) {

		$int_result_pointer = $this->SearchQuery($resource, $class, $query, $optional_params);

		$data_table = array();
		
		while ($row = $this->FetchRow($int_result_pointer)) {
			$data_table[] = $row;
		}

		return $data_table;
	}
	public function getLastSearchId() {
		return $this->int_result_pointer == 0 ? false : $this->int_result_pointer;
	}

/**
 * Gets all of the lookup values for the selected resource
 * @param string $resource Resource string (Property, User, Etc.)
 * @return array $values 
 */
	public function GetAllLookupValues($resource) {

		$this->RETSRequest($this->service_urls['GetMetadata'],
						array(
								'Type' => 'METADATA-LOOKUP_TYPE',
								'ID' => $resource.':*',
								'Format' => 'STANDARD-XML'
								)
						);

		$this->ParseXMLResponse($this->last_response_body);

		$this_table = array();

		if ($this->xml->METADATA && $this->xml->METADATA->{'METADATA-LOOKUP_TYPE'}) {

			foreach ($this->xml->METADATA->{'METADATA-LOOKUP_TYPE'} as $key) {
				if (!empty($key->attributes()->Lookup)) {
					$this_lookup = array();

					$lookup_xml_array = array();
					if ($this->is_server_version('1_7_or_above')) {
						$lookup_xml_array = $key->LookupType;
					} else {
						$lookup_xml_array = $key->Lookup;
					}

					if (is_object($lookup_xml_array)) {
						foreach ($lookup_xml_array as $look) {
							$metadataentryid = isset($look->MetadataEntryID) ? "{$look->MetadataEntryID}" : "";
							$value = isset($look->Value) ? "{$look->Value}" : "";
							$shortvalue = isset($look->ShortValue) ? "{$look->ShortValue}" : "";
							$longvalue = isset($look->LongValue) ? "{$look->LongValue}" : "";

							$this_lookup[] = array(
									'MetadataEntryID' => $metadataentryid,
									'Value' => $value,
									'ShortValue' => $shortvalue,
									'LongValue' => $longvalue
									);
						}
					}

					$this_table[] = array('Lookup' => "{$key->attributes()->Lookup}", 'Values' => $this_lookup);
				}
			}
		}

		// return the big array
		return $this_table;
	}
/**
 * Get values for an individual type (WARNING - does an API call for each LookupName)
 * @TODO refactor this to cache the results to limit API calls for loops
 * 	Maybe add a third param $cache = true, where the interface will allow a dev
 * 	to specify that it should do an 'ID' => resource:* call and cache the result 
 * 	for use in subsequent lookup value requests
 * @param string $resource Class name
 * @param string $lookupname metadata LookupName
 */
	public function GetLookupValues($resource, $lookupname) {
		$this->RETSRequest($this->service_urls['GetMetadata'],
						array(
								'Type' => 'METADATA-LOOKUP_TYPE',
								'ID' => $resource.':'.$lookupname,
								'Format' => 'STANDARD-XML'
								)
						);
		$this->ParseXMLResponse($this->last_response_body);

		$this_table = array();
		// parse XML into a nice array
		if ($this->xml->METADATA && $this->xml->METADATA->{'METADATA-LOOKUP_TYPE'}) {

			$lookup_xml_array = array();
			if ($this->is_server_version('1_7_or_above')) {
				$lookup_xml_array = $this->xml->METADATA->{'METADATA-LOOKUP_TYPE'}->LookupType;
			}
			else {
				$lookup_xml_array = $this->xml->METADATA->{'METADATA-LOOKUP_TYPE'}->Lookup;
			}

			if (is_object($lookup_xml_array)) {
				foreach ($lookup_xml_array as $key) {
					if (isset($key->Value)) {
						$metadataentryid = isset($key->MetadataEntryID) ? "{$key->MetadataEntryID}" : "";
						$value = isset($key->Value) ? "{$key->Value}" : "";
						$shortvalue = isset($key->ShortValue) ? "{$key->ShortValue}" : "";
						$longvalue = isset($key->LongValue) ? "{$key->LongValue}" : "";

						$this_table[] = array(
								'MetadataEntryID' => $metadataentryid,
								'Value' => $value,
								'ShortValue' => $shortvalue,
								'LongValue' => $longvalue
								);
					}
				}
			}
		}

		// return the big array
		return $this_table;
	}

/**
 * Gets all resources
 * @param string $id Optional resource type string (Property, User, Office, Etc.). Omit for all.
 * @return array  
 */
	public function GetMetadataResources($id = 0) {
		
		// make request
		$result = $this->RETSRequest($this->service_urls['GetMetadata'],
						array(
								'Type' => 'METADATA-RESOURCE',
								'ID' => $id,
								'Format' => 'STANDARD-XML'
								)
						);

		$this->ParseXMLResponse($this->last_response_body);

		

		$this_resource = array();

		// parse XML into a nice array
		if ($this->xml->METADATA) {
			foreach ($this->xml->METADATA->{'METADATA-RESOURCE'}->Resource as $key => $value) {
				$this_resource["{$value->ResourceID}"] = array(
						'ResourceID' => "{$value->ResourceID}",
						'StandardName'=>"{$value->StandardName}",
						'VisibleName' => "{$value->VisibleName}",
						'Description' => "{$value->Description}",
						'KeyField' => "{$value->KeyField}",
						'ClassCount' => "{$value->ClassCount}",
						'ClassVersion' => "{$value->ClassVersion}",
						'ClassDate' => "{$value->ClassDate}",
						'ObjectVersion' => "{$value->ObjectVersion}",
						'ObjectDate' => "{$value->ObjectDate}",
						'SearchHelpVersion' => "{$value->SearchHelpVersion}",
						'SearchHelpDate' => "{$value->SearchHelpDate}",
						'EditMaskVersion' => "{$value->EditMaskVersion}",
						'EditMaskDate' => "{$value->EditMaskDate}",
						'LookupVersion' => "{$value->LookupVersion}",
						'LookupDate' => "{$value->LookupDate}",
						'UpdateHelpVersion' => "{$value->UpdateHelpVersion}",
						'UpdateHelpDate' => "{$value->UpdateHelpDate}",
						'ValidationExpressionVersion' => "{$value->ValidationExpressionVersion}",
						'ValidationExpressionDate' => "{$value->ValidationExpressionDate}",
						'ValidationLookupVersion' => "{$value->ValidationLookupVersion}",
						'ValidationLookupDate' => "{$value->ValidationLookupDate}",
						'ValidationExternalVersion' => "{$value->ValidationExternalVersion}",
						'ValidationExternalDate' => "{$value->ValidationExternalDate}"
						);
			}
		}

		// send back array
		return $this_resource;
	}

	/**
	 * @see phRETS::GetMetadataResources($id);
	 * @param int $id
	 */
	public function GetMetadataInfo($id = 0) {
		return $this->GetMetadataResources($id);
	}

	/**
	 * 
	 * @param string $resource Resource (Property, User, Etc.)
	 * @param string $class Class ID (by ClassName returned from 
	 * @see phRETS::GetMetadataClasses();
	 */
	public function GetMetadataTable($resource, $class) {
		$id = $resource.':'.$class;
		// request specific metadata
		$result = $this->RETSRequest($this->service_urls['GetMetadata'],
						array(
								'Type' => 'METADATA-TABLE',
								'ID' => $id,
								'Format' => 'STANDARD-XML'
								)
						);

		$this->ParseXMLResponse($this->last_response_body);

		$this_table = array();

		// parse XML into a nice array
		if ($this->xml->METADATA) {
			foreach ($this->xml->METADATA->{'METADATA-TABLE'}->Field as $key) {
				$this_table[] = array(
						'SystemName' => "{$key->SystemName}",
						'StandardName' => "{$key->StandardName}",
						'LongName' => "{$key->LongName}",
						'DBName' => "{$key->DBName}",
						'ShortName' => "{$key->ShortName}",
						'MaximumLength' => "{$key->MaximumLength}",
						'DataType' => "{$key->DataType}",
						'Precision' => "{$key->Precision}",
						'Searchable' => "{$key->Searchable}",
						'Interpretation' => "{$key->Interpretation}",
						'Alignment' => "{$key->Alignment}",
						'UseSeparator' => "{$key->UseSeparator}",
						'EditMaskID' => "{$key->EditMaskID}",
						'LookupName' => "{$key->LookupName}",
						'MaxSelect' => "{$key->MaxSelect}",
						'Units' => "{$key->Units}",
						'Index' => "{$key->Index}",
						'Minimum' => "{$key->Minimum}",
						'Maximum' => "{$key->Maximum}",
						'Default' => "{$key->Default}",
						'Required' => "{$key->Required}",
						'SearchHelpID' => "{$key->SearchHelpID}",
						'Unique' => "{$key->Unique}",
						'MetadataEntryID' => "{$key->MetadataEntryID}",
						'ModTimeStamp' => "{$key->ModTimeStamp}",
						'ForeignKeyName' => "{$key->ForiengKeyName}",
						'ForeignField' => "{$key->ForeignField}",
						'InKeyIndex' => "{$key->InKeyIndex}"
						);
			}
		}

		// return the big array
		return $this_table;
	}


	public function GetMetadata($resource, $class) {
		return $this->GetMetadataTable($resource, $class);
	}

	/**
 	* 	request basic metadata information 
 	*/
	public function GetMetadataObjects($resource) {
		
		$result = $this->RETSRequest($this->service_urls['GetMetadata'],
						array(
								'Type' => 'METADATA-OBJECT',
								'ID' => $resource,
								'Format' => 'STANDARD-XML'
								)
						);

		$this->ParseXMLResponse($this->last_response_body);
		$return_data = array();

		if (isset($this->xml->METADATA->{'METADATA-OBJECT'})) {
			// parse XML into a nice array
			foreach ($this->xml->METADATA->{'METADATA-OBJECT'} as $key => $value) {
				foreach ($value->Object as $key) {
					if (!empty($key->ObjectType)) {
						$return_data[] = array(
								'MetadataEntryID' => "{$key->MetadataEntryID}",
								'VisibleName' => "{$key->VisibleName}",
								'ObjectTimeStamp' => "{$key->ObjectTimeStamp}",
								'ObjectCount' => "{$key->ObjectCount}",
								'ObjectType' => "{$key->ObjectType}",
								'StandardName' => "{$key->StandardName}",
								'MimeType' => "{$key->MimeType}",
								'Description' => "{$key->Description}"
								);
					}
				}
			}
		}

		// send back array
		return $return_data;
	}

	/**
	 * Get metadata classes
	 * @param string $id Resource name (Property, User, Etc.)
	 */
	public function GetMetadataClasses($id) {
		// request basic metadata information
		$this->RETSRequest($this->service_urls['GetMetadata'],
						array(
								'Type' => 'METADATA-CLASS',
								'ID' => $id,
								'Format' => 'STANDARD-XML'
								)
						);

		$this->ParseXMLResponse($this->last_response_body);
		
		$return_data = array();

		// parse XML into a nice array
		if ($this->xml->METADATA) {
			foreach ($this->xml->METADATA->{'METADATA-CLASS'} as $key => $value) {
				foreach ($value->Class as $key) {
					if (!empty($key->ClassName)) {
						$return_data[] = array(
								'ClassName' => "{$key->ClassName}",
								'VisibleName' => "{$key->VisibleName}",
								'StandardName' => "{$key->StandardName}",
								'Description' => "{$key->Description}",
								'TableVersion' => "{$key->TableVersion}",
								'TableDate' => "{$key->TableDate}",
								'UpdateVersion' => "{$key->UpdateVersion}",
								'UpdateDate' => "{$key->UpdateDate}",
								'ClassTimeStamp' => "{$key->ClassTimeStamp}",
								'DeletedFlagField' => "{$key->DeletedFlagField}",
								'DeletedFlagValue' => "{$key->DeletedFlagValue}",
								'HasKeyIndex' => "{$key->HasKeyIndex}"
								);
					}
				}
			}
		}

		// send back array
		return $return_data;
	}


	/**
	 * request basic metadata information
	 */		
	public function GetMetadataTypes($id = 0) {
		$this->RETSRequest($this->service_urls['GetMetadata'],
						array(
								'Type' => 'METADATA-CLASS',
								'ID' => $id,
								'Format' => 'STANDARD-XML'
								)
						);
		$this->ParseXMLResponse($this->last_response_body);
		
		$return_data = array();

		// parse XML into a nice array
		if ($this->xml->METADATA) {
			foreach ($this->xml->METADATA->{'METADATA-CLASS'} as $key => $value) {
				$resource = $value['Resource'];
				$this_resource = array();
				foreach ($value->Class as $key) {
					if (!empty($key->ClassName)) {
						$this_resource[] = array(
								'ClassName' => "{$key->ClassName}",
								'VisibleName' => "{$key->VisibleName}",
								'StandardName' => "{$key->StandardName}",
								'Description' => "{$key->Description}",
								'TableVersion' => "{$key->TableVersion}",
								'TableDate' => "{$key->TableDate}",
								'UpdateVersion' => "{$key->UpdateVersion}",
								'UpdateDate' => "{$key->UpdateDate}"
								);
					}
				}

				// prepare 2-deep array
				$return_data[] = array('Resource' => "{$resource}", 'Data' => $this_resource);
			}
		}

		// send back array
		return $return_data;
	}


	public function GetServerSoftware() {
		return $this->server_software;
	}


	public function GetServerVersion() {
		return $this->server_version;
	}

	/**
	 * Check RETS for a type authentication support
	 * @param string $type basic / digest. authentication type. 
	 * @return boolean true when supported, false for no support
	 */
	public function is_auth_type_supported($type) {
		if ($type == "basic") {
			return $this->auth_support_basic;
		}
		if ($type == "digest") {
			return $this->auth_support_digest;
		}
		throw new phRETSException('Unknown Authentication Type: ' . $type);
	}

	/**
	 * Gets server info
	 * @return array $info
	 */
	public function GetServerInformation() {
		
		$this->RETSRequest($this->service_urls['GetMetadata'],
						array(
								'Type' => 'METADATA-SYSTEM',
								'ID' => 0,
								'Format' => 'STANDARD-XML'
								)
						);


		$this->ParseXMLResponse($this->last_response_body);

		$system_id = "";
		$system_description = "";
		$system_comments = "";

		if ($this->is_server_version("1_5_or_below")) {
			if (isset($this->xml->METADATA->{'METADATA-SYSTEM'}->System->SystemID)) {
				$system_id = "{$this->xml->METADATA->{'METADATA-SYSTEM'}->System->SystemID}";
			}
			if (isset($this->xml->METADATA->{'METADATA-SYSTEM'}->System->SystemDescription)) {
				$system_description = "{$this->xml->METADATA->{'METADATA-SYSTEM'}->System->SystemDescription}";
			}
			$timezone_offset = "";
		} else {
			//@codeCoverageIgnoreStart
			if (isset($this->xml->METADATA->{'METADATA-SYSTEM'}->SYSTEM->attributes()->SystemID)) {
				$system_id = "{$this->xml->METADATA->{'METADATA-SYSTEM'}->SYSTEM->attributes()->SystemID}";
			}
			if (isset($this->xml->METADATA->{'METADATA-SYSTEM'}->SYSTEM->attributes()->SystemDescription)) {
				$system_description = "{$this->xml->METADATA->{'METADATA-SYSTEM'}->SYSTEM->attributes()->SystemDescription}";
			}
			if (isset($this->xml->METADATA->{'METADATA-SYSTEM'}->SYSTEM->attributes()->TimeZoneOffset)) {
				$timezone_offset = "{$this->xml->METADATA->{'METADATA-SYSTEM'}->SYSTEM->attributes()->TimeZoneOffset}";
			}
		}

		if (isset($this->xml->METADATA->{'METADATA-SYSTEM'}->SYSTEM->Comments)) {
			$system_comments = "{$this->xml->METADATA->{'METADATA-SYSTEM'}->SYSTEM->Comments}";
		}
			//@codeCoverageIgnoreEnd

		return array(
				'SystemID' => $system_id,
				'SystemDescription' => $system_description,
				'TimeZoneOffset' => $timezone_offset,
				'Comments' => $system_comments
				);
	}

	/**
	 * Logs out current RETS Session
	 */
	public function Disconnect () {
		$this->RETSRequest($this->service_urls['Logout']);
		// close cURL connection
		curl_close($this->curl_handle);

		if ($this->debug_mode == true && $this->debug_file_handle && is_resource($this->debug_file_handle)) {
			// close cURL debug log file handler
			fclose($this->debug_file_handle);
		}

		if (file_exists($this->cookie_file)) {
			@unlink($this->cookie_file);
		}
		$this->is_connected = false;
		return true;

	}

	/**
	 * add static header for cURL requests
	 * @param string $name header key
	 * @param string $value raw HTTP header
	 */
	private function AddHeader($name, $value) {
		$this->static_headers[$name] = $value;
		return true;
	}

	/**
	 * Parse the XML response and set it to phRETS::$xml
	 * @param string $data raw XML data
	 * @return null 
	 */
	public function ParseXMLResponse( $data ) {
		if (empty($data)) {
			throw new retsXMLParsingException('Error parsing empty string. No Data.');			
		}
		$xml = @simplexml_load_string($data);
		if ( !is_object($xml) ) {
			throw new retsXMLParsingException('Error parsing string into XML. Data: ' . $data);			
		} 
		if (0 != $xml['ReplyCode'] ) {
			throw new retsException($xml['ReplyText'], (int) $xml['ReplyCode']);
		}
		$this->save_last_request();
		$this->xml = $xml;
	}
	private function save_last_request () {
		$this->last_request['ReplyCode'] = "{$this->xml['ReplyCode']}";
		$this->last_request['ReplyText'] = "{$this->xml['ReplyText']}";
	}

	/**
	 * Low Level RETS transaction implementation
	 * @param string $service_url use the public phRETS->service_urls array for the URL
	 * @param array $parameters RETS transaction
	 * @return array array($this->last_response_headers_raw, $response_body);
	 */
	public function RETSRequest($request_service_url, $parameters = "") {
		
		//Reset per-request class variables
		
		$this->last_response_headers = array();
		$this->last_response_headers_raw =	$this->last_remembered_header = "";

		if (empty($request_service_url)) {
			throw new phRETSException('RETSRequest called but Action passed has no value.  Failed login?');
		}

		$parse_results = parse_url($request_service_url, PHP_URL_HOST);
		if (empty($parse_results)) {
			// login transaction gave a relative path for this action
			$request_url = $this->server_protocol.'://'.$this->server_hostname.':'.$this->server_port.''.$request_service_url;
		}
		else {
			// login transaction gave an absolute path for this action
			$request_url = $request_service_url;
		}

		// build query string from arguments
		$request_arguments = "";
		if (is_array($parameters)) {
			$request_arguments = http_build_query($parameters);
		}

		// append URL query arguments if necessary
		if (!empty($request_arguments)) {
			$request_url = $request_url .'?'. $request_arguments;
		}

		// build headers to pass in cURL
		$request_headers = "";
		if (is_array($this->static_headers)) {
			foreach ($this->static_headers as $key => $value) {
				$request_headers .= "{$key}: {$value}\r\n";
			}
		}

		if ($this->ua_auth == true) {
			$session_id_to_calculate_with = "";

			// calculate RETS-UA-Authorization header
			$ua_a1 = md5($this->static_headers['User-Agent'] .':'. $this->ua_pwd);
			$session_id_to_calculate_with = ($this->use_interealty_ua_auth == true) ? "" : $this->session_id;
			$ua_dig_resp = md5(trim($ua_a1) .':'. trim($this->request_id) .':'. trim($session_id_to_calculate_with) .':'. trim($this->static_headers['RETS-Version']));
			$request_headers .= "RETS-UA-Authorization: Digest {$ua_dig_resp}\r\n";
		}

		$this->last_request_url = $request_url;

		//cURL		
		$this->initialize_curl();
		curl_setopt($this->curl_handle, CURLOPT_URL, $request_url);
		curl_setopt($this->curl_handle, CURLOPT_HTTPHEADER, array(trim($request_headers)));
		$this->last_response_body = curl_exec($this->curl_handle);

		
		$response_code = curl_getinfo($this->curl_handle, CURLINFO_HTTP_CODE);
		if (200 !== $response_code) {
			throw new retsException('HTTP Error. Response code: '.$response_code . $this->last_response_body, $response_code);
		}
		
		if ($this->debug_mode == true && ! empty($this->last_response_body) && $this->debug_file_handle) {
			fwrite($this->debug_file_handle, $this->last_response_body ."\n");
		}

		if (isset($this->last_response_headers['WWW-Authenticate'])) {
			if (strpos($this->last_response_headers['WWW-Authenticate'], 'Basic') !== false) {
				$this->auth_support_basic = true;
			}
			if (strpos($this->last_response_headers['WWW-Authenticate'], 'Digest') !== false) {
				$this->auth_support_digest = true;
			}
		}

		if (isset($this->last_response_headers['RETS-Version'])) {
			$this->server_version = $this->last_response_headers['RETS-Version'];
		}

		if (isset($this->last_response_headers['Server'])) {
			$this->server_software = $this->last_response_headers['Server'];
		}

		if (isset($this->last_response_headers['Set-Cookie'])) {
			if (preg_match('/RETS-Session-ID\=(.*?)(\;|\s+|$)/', $this->last_response_headers['Set-Cookie'], $matches)) {
				$this->session_id = $matches[1];
			}
		}
	}


	private function read_custom_curl_headers($handle, $call_string) {
		$this->last_response_headers_raw .= $call_string;
		$header = null;
		$value = null;

		$trimmed_call_string = trim($call_string);

		if (strpos($call_string, ':') !== false) {
			@list($header, $value) = explode(':', $trimmed_call_string, 2);
		}

		$header = trim($header);
		$value = trim($value);

		if ( preg_match('/^HTTP\/1/', $trimmed_call_string) ) {
			$value = $trimmed_call_string;
			$header = "HTTP";
		}

		if (!empty($header)) {
			// new header
			$this->last_response_headers[$header] = $value;
			$last_remembered_header = $header;
		} elseif (!empty( $trimmed_call_string )) {
			// continuation of last header.  append to previous
			$this->last_response_headers[$this->last_remembered_header] .= $trimmed_call_string;
		} else { }

		return strlen($call_string);
	}

	/**
	 * encapsulates rets server version polymorphisms 
	 * @param string $check_version 1_5_or_below or 1_7_or_above
	 * @return boolean
	 */
	public function is_server_version($check_version) {
		if ($check_version == "1_5_or_below") {
			if ($this->GetServerVersion() == "RETS/1.5" || $this->GetServerVersion() == "RETS/1.0") {
				return true;
			} else {
				return false;
			}
		}
		if ($check_version == "1_7_or_above") {
			if ($this->GetServerVersion() == "RETS/1.7" || $this->GetServerVersion() == "RETS/1.7.1" || $this ->GetServerVersion() == "RETS/1.7.2" || $this->GetServerVersion() == "RETS/1.8") {
				return true;
			} else {
				return false;
			}
		}
		if ($check_version == '1_0') {
			if ( $this->GetServerVersion() == 'RETS/1.0') {
				return true;
			} else {
				return false;
			}
		}
		return false;
	}


	private function fix_encoding($in_str) {
		if ($this->disable_encoding_fix == true || !function_exists("mb_detect_encoding")) {
			return $in_str;
		}

		$in_str = preg_replace('/\&\s/', '&amp; ', $in_str);
		$cur_encoding = mb_detect_encoding($in_str);
		if ($cur_encoding == "UTF-8" && mb_check_encoding($in_str, "UTF-8")) {
			return $in_str;
		}
		else {
			return utf8_encode($in_str);
		}
	}


	/**
	 * Public interface for setting class variables
	 * @param string $name name of setting. Values include:
	 * 	cookie_file, debug_file, debug_mode, compression_enabled, 
	 *	force_ua_authentication, disable_follow_location,force_basic_authentication,
	 *	use_interealty_ua_auth, catch_last_response, disable_encoding_fix, offset_support
	 *	override_offset_protection
	 * @param string $value
	 * @return boolean true on success, false on failure
	 * @todo refactor param
	 */
	public function SetParam($name, $value) {
		switch ($name) {
			case "cookie_file":
				$this->cookie_file = $value;
				break;
			case "debug_file":
				$this->debug_file = $value;
				break;
			case 'debug':
			case "debug_mode":
				$this->debug_mode = $value;
				break;
			case "compression_enabled":
				$this->compression_enabled = $value;
				break;
			case "force_ua_authentication":
				$this->ua_auth = $value;
				break;
			case "disable_follow_location":
				$this->disable_follow_location = $value;
				break;
			case "force_basic_authentication":
				$this->force_basic_authentication = $value;
				break;
			case "use_interealty_ua_auth":
				$this->use_interealty_ua_auth = $value;
				break;
			case "disable_encoding_fix":
				$this->disable_encoding_fix = $value;
				break;
			case "offset_support":
				$this->offset_support = $value;
				break;
			case "override_offset_protection":
				$this->override_offset_protection = $value;
				break;
			default:
				throw new retsException('Unknown param name: '. $name);
				break;
		}
		return true;
	}


}

endif;