DETAILED_REGISTERS_TEMPLATE = """
<style>
    table { border-collapse: collapse; }
    td {
        border-bottom: solid 1px black !important;
        border-top: solid 1px black !important;  
    }
</style>
<h4>Registers:</h4>
<table>
    {% for reg in registers %}
    <tr>
        <td class="t-cell"><strong>{{reg[0]}}:</strong></td>
        <td class="reg-val">{{reg[1]}}</td>
    </tr>
    {% endfor %}
</table>
"""

NZCV_FLAGS_VIEW = """
<h4>NZCV Flags</h4>
<table>
<tr>
    <th>N</th><th>Z</th><th>C</th><th>V</th>
</tr>
<tr>
    <td>{{n}}</td>
    <td>{{z}}</td>
    <td>{{c}}</td>
    <td>{{v}}</td>
</tr>
</table>
"""