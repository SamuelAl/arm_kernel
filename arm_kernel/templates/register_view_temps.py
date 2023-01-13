REGISTERS_TEMPLATE = """
<style>
    table { border-collapse: collapse; }
    td {
        border-bottom: solid 1px black !important;
        border-top: solid 1px black !important;  
    }
</style>
<h3>Registers:</h3>
<table>
    <tr>
        {% for i in range(reg_count//2) %}
        <td class="t-cell"><strong>{{registers[i][0]}}:</strong></td>
        <td class="t-cell">{{registers[i][1]}}</td>
        {% endfor %}
    </tr>
    <tr>
        {% for i in range(reg_count//2,reg_count) %}
        <td class="t-cell"><strong>{{registers[i][0]}}:</strong></td>
        <td class="t-cell">{{registers[i][1]}}</td>
        {% endfor %}
    </tr>
</table>
"""

DETAILED_REGISTERS_TEMPLATE = """
<style>
    table { border-collapse: collapse; }
    td {
        border-bottom: solid 1px black !important;
        border-top: solid 1px black !important;  
    }
</style>
<h3>Registers:</h3>
<table>
    <tr>
        {% for i in range(6) %}
        <td class="t-cell"><strong>{{registers[i][0]}}:</strong></td>
        <td class="t-cell">{{registers[i][1]}}</td>
        {% endfor %}
    </tr>
    <tr>
        {% for i in range(6,13) %}
        <td class="t-cell"><strong>{{registers[i][0]}}:</strong></td>
        <td class="t-cell">{{registers[i][1]}}</td>
        {% endfor %}
    </tr>
</table>
<table>
    <tr>
        <td><strong>{{registers[13][0]}}:</strong></td>
        <td>{{registers[13][1]}}</td>
    </tr>
    <tr>
        <td><strong>{{registers[14][0]}}:</strong></td>
        <td>{{registers[14][1]}}</td>
    </tr>
</table>
"""