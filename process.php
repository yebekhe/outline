<?php

// Include the functions file
require "functions.php";

// Enable error reporting
ini_set("display_errors", 1);
ini_set("display_startup_errors", 1);
error_reporting(E_ERROR | E_PARSE);

function getTelegramChannelConfigs($username)
{
    $sourceArray = explode(",", $username);
    foreach ($sourceArray as $source) {
        $html = file_get_contents("https://t.me/s/" . $source);
        
        $types = ["vmess", "vless", "trojan", "ss", "tuic", "hysteria", "hysteria2", "hy2"];
        $configs = [];
        foreach ($types as $type) {
            $configs[$type] = getConfigItems($type, $html);
        }
        file_put_contents("collect", json_encode($configs, JSON_PRETTY_PRINT));
        $output = "";
        foreach ($configs as $type => $configsArray) {
            foreach ($configsArray as $config) {
                if (is_valid($config)) {
                    $fixedConfig = str_replace("amp;", "", removeAngleBrackets($config));
                    $correctedConfig = correctConfig("{$fixedConfig}", $type);
                    $output .= "{$correctedConfig}\n";
                }
            }
        }
    }
    return $output;
}

$source = getenv('CONFIGS_SOURCE');
$telegramConfigs = generateHiddifyTags() . "\n\n" .  str_replace("&amp;", "&", getTelegramChannelConfigs($source));

file_put_contents("subscription/base64", base64_encode($telegramConfigs));
file_put_contents("subscription/normal", $telegramConfigs);
