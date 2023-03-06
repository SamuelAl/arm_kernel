SIMPLE_DISASSEMBLY_VIEW = """
<h4>Disassembly:</h4>
<p>{{disassembly_str}}</p>
<p>{{count}}</p>
<table style='font-family:"Courier New", Courier, monospace;'>
<tr>
    <th>Address</th>
    <th>Bytes</th>
    <th>Mnemonic</th>
    <th>Operators</th>
</tr>
{% for row in disassembly %}
<tr>

    <td>{{row[0]}}</td>
    <td>{{row[1]}}</td>
    <td>{{row[2]}}</td>
    <td style="text-align: left">{{row[3]}}</td>

</tr>
{% endfor %}
</table>
"""