<?php
header("Content-type: application/json;");

// Enable error reporting
ini_set("display_errors", 1);
ini_set("display_startup_errors", 1);
error_reporting(E_ERROR | E_PARSE);

function removeAngleBrackets($link) {
  return preg_replace('/<.*?>/', '', $link);
}

function is_ip($string)
{
    $ip_pattern = '/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/';
    if (preg_match($ip_pattern, $string)) {
        return true;
    } else {
        return false;
    }
}

function ParseShadowsocksToOutline($config_str)
{
    // Parse the config string as a URL
    $url = parse_url($config_str);

    // Extract the encryption method and password from the user info
    list($encryption_method, $password) = explode(
        ":",
        base64_decode($url["user"])
    );

    // Extract the server address and port from the host and path
    $server_address = $url["host"];
    $server_port = $url["port"];

    // Extract the name from the fragment (if present)
    $name = isset($url["fragment"]) ? urldecode($url["fragment"]) : null;
    
    $jsonObject = [
        'server' => $server_address,
        'server_port' => $server_port,
        'password' => $password,
        'method' => $encryption_method,
        'prefix' => $name,
    ];

    // Return the server configuration as a JSON string
    return json_encode($jsonObject);
}

function ip_info($ip)
{
    // Check if the IP is from Cloudflare
    if (is_cloudflare_ip($ip)) {
        $traceUrl = "http://$ip/cdn-cgi/trace";
        $traceData = convertToJson(file_get_contents($traceUrl));
        $country = $traceData['loc'] ?? "CF";
        return (object) [
            "country" => $country,
        ];
    }

    if (is_ip($ip) === false) {
        $ip_address_array = dns_get_record($ip, DNS_A);
        if (empty($ip_address_array)) {
            return null;
        }
        $randomKey = array_rand($ip_address_array);
        $ip = $ip_address_array[$randomKey]["ip"];
    }

    // List of API endpoints
    $endpoints = [
        "https://ipapi.co/{ip}/json/",
        "https://ipwhois.app/json/{ip}",
        "http://www.geoplugin.net/json.gp?ip={ip}",
        "https://api.ipbase.com/v1/json/{ip}",
    ];

    // Initialize an empty result object
    $result = (object) [
        "country" => "XX",
    ];

    // Loop through each endpoint
    foreach ($endpoints as $endpoint) {
        // Construct the full URL
        $url = str_replace("{ip}", $ip, $endpoint);

        $options = [
            "http" => [
                "header" =>
                    "User-Agent: Mozilla/5.0 (iPad; U; CPU OS 3_2 like Mac OS X; en-us) AppleWebKit/531.21.10 (KHTML, like Gecko) Version/4.0.4 Mobile/7B334b Safari/531.21.102011-10-16 20:23:10\r\n", // i.e. An iPad
            ],
        ];

        $context = stream_context_create($options);
        $response = file_get_contents($url, false, $context);

        if ($response !== false) {
            $data = json_decode($response);

            // Extract relevant information and update the result object
            if ($endpoint == $endpoints[0]) {
                // Data from ipapi.co
                $result->country = $data->country_code ?? "XX";
            } elseif ($endpoint == $endpoints[1]) {
                // Data from ipwhois.app
                $result->country = $data->country_code ?? "XX";
            } elseif ($endpoint == $endpoints[2]) {
                // Data from geoplugin.net
                $result->country = $data->geoplugin_countryCode ?? "XX";
            } elseif ($endpoint == $endpoints[3]) {
                // Data from ipbase.com
                $result->country = $data->country_code ?? "XX";
            }
            // Break out of the loop since we found a successful endpoint
            break;
        }
    }

    return $result;
}

function cidr_match($ip, $range) {
    list($subnet, $bits) = explode('/', $range);
    if ($bits === null) {
        $bits = 32;
    }
    $ip = ip2long($ip);
    $subnet = ip2long($subnet);
    $mask = -1 << (32 - $bits);
    $subnet &= $mask;
    return ($ip & $mask) == $subnet;
}

function is_cloudflare_ip($ip)
{
    // Get the Cloudflare IP ranges
    $cloudflare_ranges = file_get_contents('https://www.cloudflare.com/ips-v4');
    $cloudflare_ranges = explode("\n", $cloudflare_ranges);

    foreach ($cloudflare_ranges as $range) {
        if (cidr_match($ip, $range)) {
            return true;
        }
    }

    return false;
}

function getFlags($country_code)
{
    $flag = mb_convert_encoding(
        "&#" . (127397 + ord($country_code[0])) . ";",
        "UTF-8",
        "HTML-ENTITIES"
    );
    $flag .= mb_convert_encoding(
        "&#" . (127397 + ord($country_code[1])) . ";",
        "UTF-8",
        "HTML-ENTITIES"
    );
    return $flag;
}

function is_valid($input)
{
    if (stripos($input, "…") !== false or stripos($input, "...") !== false) {
        return false;
    }
    return true;
}

function getConfigItems($type, $input)
{
    preg_match_all("#>" . $type . "://(.*?)<br#", $input, $items);
    return $items[1];
}


function isBase64($input)
{
    if (base64_encode(base64_decode($input)) === $input) {
        return true;
    }

    return false;
}


function modifyVpnString($vpnString) {
    // Find the position of the hashtag
    $hashtagPos = strpos($vpnString, '#');
    if ($hashtagPos === false) {
        return 'No hashtag found in the string.';
    }

    // Extract the part before and after the hashtag
    $beforeHashtag = substr($vpnString, 0, $hashtagPos);
    $afterHashtag = substr($vpnString, $hashtagPos + 1);

    // Parse the beforeHashtag part to extract config type, IP, and port
    $parsedUrl = parse_url($beforeHashtag);
    if (isBase64($parsedUrl["user"])) {
            $parsedUrl["user"] = base64_decode($parsedUrl["user"]);
    }
    list($encryption_method, $password) = explode(
        ":",
        $parsedUrl["user"]
    );
    $hostAndPort = isset($parsedUrl['host']) ? $parsedUrl['host'] : '';
    $ipLocation = ip_info($parsedUrl['host'])->country;
    $ipFlag = getFlags($ipLocation);
    if (isset($parsedUrl['port'])) {
        $hostAndPort .= ':' . $parsedUrl['port'];
    }

    // Combine the new afterHashtag content
    $modifiedAfterHashtag = $ipFlag . $ipLocation . "-" . $password;

    // Combine the parts back together
    return $beforeHashtag . '#' . $modifiedAfterHashtag;
}

function getTelegramChannelConfigs($username)
{
    $sourceArray = explode(",", $username);
    foreach ($sourceArray as $source) {
        $html = file_get_contents("https://t.me/s/" . $source);
        $type = "ss";
        $configs = [];
        $configs[$type] = getConfigItems($type, $html);
        $output = "";
        foreach ($configs as $type => $configList) {
            foreach ($configList as $soloConfig) {
                if (is_valid($soloConfig)) {
                    $output .=
                        modifyVpnString($type .
                        "://" .
                        removeAngleBrackets($soloConfig)) .
                        "
";
                }
            }
        }
    }
    
    return $output;
}

$base64 = filter_input(INPUT_GET, "b", FILTER_SANITIZE_STRING) ?? "true";
$source = getenv('CONFIGS_SOURCE');
$telegramConfigs = str_replace("&amp;", "&", getTelegramChannelConfigs($source));
$telegramConfigsArray = explode("\n", $telegramConfigs);
$lastItemKey = count($telegramConfigsArray) - 1;
$ssToOutline = ParseShadowsocksToOutline($telegramConfigsArray[$lastItemKey]);

file_put_contents("subscription/base64", base64_encode($telegramConfigs));
file_put_contents("subscription/normal", $telegramConfigs);
file_put_contents("subscription/outline", $ssToOutline);
