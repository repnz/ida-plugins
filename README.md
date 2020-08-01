# IDA Plugins

My collection of plugins for IDA Pro.

## Installing plugins

- Install [sark](https://github.com/tmr232/Sark). 
- Take the plugins loader plugin: 

https://github.com/tmr232/Sark/blob/master/plugins/plugin_loader.py

It allows you to manage your plugins by editing a plugins.list file.

- Put plugin_loader.py in the "plugins" directory of IDA.
- Open IDA as administrator and close it (so the plugins.list file will be created at %idafolder%\cfg)
- Add the path of the wanted plugin in this file (for example, c:\\...\\reg_xref.py)

 
## Register Cross References

When looking at disassembly, it's useful to find usages of a register - That's why I created [reg_xref](/reg_xref.py). 
Simply install the plugin and use Shift-Z to get a view like this:

![Alt Text](/pics/reg_xref.png)

*A notable mention is [Oregami](https://github.com/shemesh999/oregami),
But the main difference is that Oregami tries to analyze and find where the same value is used, and display
only these references. This is useful for example in case you want to mark a register as a pointer to a structure. 
I wanted something simpler that shows all of the references to a register inside a function.*


