<?php
header("Content-type: application/json;");

// Enable error reporting
ini_set("display_errors", 1);
ini_set("display_startup_errors", 1);
error_reporting(E_ERROR | E_PARSE);

function removeAngleBrackets($link) {
  return preg_replace('/<.*?>/', '', $link);
}

function getIpDetails($ipAddress, $returnIsoCodeOnly = "false") {
    $apiKey = getenv('FIND_IP_API_KEY');
    // Construct the URL with the IP address and API key
    $url = "https://api.findip.net/{$ipAddress}/?token={$apiKey}";
    
    // Fetch the content of the URL
    $response = file_get_contents($url);
    
    // Check if the content was fetched successfully
    if ($response === false) {
        throw new Exception("Failed to fetch content from the URL.");
    }
    
    // Decode the JSON response
    $data = json_decode($response, true);
    
    // Check if the JSON decoding was successful
    if ($data === null) {
        throw new Exception("Failed to decode JSON response.");
    }
    
    // If the $returnIsoCodeOnly parameter is true, return only the ISO code of the country
    if ($returnIsoCodeOnly === "true" && isset($data['country']['iso_code'])) {
        return ["iso_code" => $data['country']['iso_code']];
    }
    
    // Return the decoded data
    return $data;
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
    $ipLocation = getIpDetails($parsedUrl['host'], "true")["iso_code"];
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
    $html = file_get_contents("https://t.me/s/" . $username);
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
    return $output;
}

$base64 = filter_input(INPUT_GET, "b", FILTER_SANITIZE_STRING) ?? "true";
$source = getenv('CONFIGS_SOURCE');

file_put_contents("subscription/base64", base64_encode(str_replace("&amp;", "&", getTelegramChannelConfigs($source))));
file_put_contents("subscription/normal", str_replace("&amp;", "&", getTelegramChannelConfigs($source)));
