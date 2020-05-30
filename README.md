# Frida Plugin (v1.0 alpha)
Author: **Chame1eon**

_A plugin to integrate the Frida dynamic instrumentation toolkit into Binary Ninja._

## Description:

This plugin makes use of the Frida dynamic instrumentation framework to simplify dynamic analysis within Binary Ninja. The plugin uses function definitions and type information, either identified by Binary Ninja or user inputted, to define Frida native functions automatically. To intercept a function, all a user needs to do is select the intercept button from the option menu. Once a function is being intercepted, whenever that function is called, by default, the arguments and return value will be logged to the Binary Ninja log. The behaviour of the Frida hooks can also be modified by a user. A demonstration video of the plugin in use in the following video:

[Binary Ninja - Frida Plugin](http://sendvid.com/vw7froy5)


### Use Guide

#### Start Plugin

After installing the plugin, from either the tools menu or by right clicking on the binary view window, you can select the option "Frida: Start Plugin". Selecting this option will bring up a window asking you to select the device you want the plugin to use, any device supported by Frida should also be supported by this plugin. For example, Android and iOS devices should also appear listed here if they are plugged in via USB.

#### Attach to Process

Once you have the process you want to analyse running, you can select the option "Frida: Attach to Process". Choosing this option will provide you with a list of currently running processes on the system you are targeting. Selecting one of those processes will trigger the plugin to use Frida to attach to that process.

#### Start Process

Use this option to spawn a new process and immediately attach Frida to it. Select the option "Frida: Start and Attach Process".

#### Select Module (Optional)

By default, this plugin will use the name of the binary you are analysing to select the target module. For example, if you currently have libssl.so loaded into Binary Ninja, then the plugin will look for that module in the process address. However, if the binary name cannot be found in the process' address space, then the module must be selected manually by running the "Frida: Select Target Module" menu option.

#### Intercept Function

Now that the plugin is running, you can start intercepting functions within the binary. To intercept a function all you need to do is right click within that function and select "Frida: Intercept Function". Providing there were no errors, that function will now be intercepted by Frida and any time that function is called a log message will be printed with the argument values and return value.

#### Modify Intercept

To change the default behaviour for an intercepted function, you can use the option "Frida: Modify Intercept". Opening this window opens two Multiline input fields. Inside those fields you can enter JavaScript to be executed before and after the function has been run. Above each of the fields is a label to show what the existing hook looks like.

#### Remove Intercept

Using "Frida: Remove Intercept" will safely remove the intercept from the Frida agent.

#### Frida: Reload

When modifying function information in Binary Ninja, such as parameter types, there is currently no way to be notified of these events. Therefore, to update the Frida intercepts, in these cases, you will need to manually call "Frida: Reload".

#### Frida: Stop Plugin

Safely removes all the hooks from the attached process, before disconnecting from the process.


### Future:
* Allow instruction level interception
* Add support for using the Frida Stalker
* Support process patching using Frida
* Frida Spawn

### Warnings:
* The Binary Ninja interaction API is, currently, does not support injecting text into a Multiline Field. As a result, hook modification requires a user to retype what they had previously.

## Minimum Version

This plugin requires the following minimum version of Binary Ninja:

 * release - 9999
 * dev - 1.0.dev-576


## Required Dependencies

The following dependencies are required for this plugin:

 * pip - frida
 * installers - 
 * other - 
 * apt - 


## License

This plugin is released under a [MIT](LICENSE) license.


