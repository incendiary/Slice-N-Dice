using System;
using System.Collections;
using System.Collections.Generic;
using System.IO;
// Check if a file path argument is provided
if (args.Length != 1)
{
    Console.WriteLine("Usage: Dice.exe <config_file> <target_file>");
    Environment.Exit(1);
}

string configFilePath = args[0];
// string targetFilePath = args[1];


// Read and parse the configuration file
var config = ReadConfiguration(configFilePath);

foreach (KeyValuePair<string, string> kvp in config)
{
    //textBox3.Text += ("Key = {0}, Value = {1}", kvp.Key, kvp.Value);
    Console.WriteLine("Key = {0}, Value = {1}", kvp.Key, kvp.Value);

}

Console.WriteLine(config["NumberOfFiles"]);

Dictionary<string, string> ReadConfiguration(string filePath)
{
    var config = new Dictionary<string, string>();

    // Check if the file exists
    if (!File.Exists(filePath))
    {
        Console.WriteLine("Configuration file not found.");
        Environment.Exit(1);
    }

    // Read the file line by line
    foreach (var line in File.ReadAllLines(filePath))
    {
        // Parse the line to get the key and value
        var parts = line.Split('=');
        if (parts.Length == 2)
        {
            string key = parts[0].Trim();
            string value = parts[1].Trim();
            config[key] = value;
        }
    }

    return config;
}
