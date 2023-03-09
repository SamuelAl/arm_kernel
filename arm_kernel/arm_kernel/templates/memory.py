MEMORY_WORD_VIEW = """
<h4>Memory:</h4>
<table style='font-family:"Courier New", Courier, monospace;'>
<tr>
    <th>Address</th>
    <th>Content</th>
</tr>
<tr
{% for row in content %}
    <tr>
        <td>{{row[0]}}</td>
        {% for col in row[1] %}
        <td>{{col}}</td>
        {% endfor %}
    </tr>
{% endfor %}
</table>
"""