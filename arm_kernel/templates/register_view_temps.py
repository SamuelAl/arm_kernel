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