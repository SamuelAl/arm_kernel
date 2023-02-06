MEMORY_WORD_VIEW = """
<h4>Memory:</h4>
<table>
<tr>
    <th>Address</th>
    <th>Content</th>
</tr>
<tr
{% for row in content %}
    <tr>
        <td>{{row[0]}}</td>
        <td>{{row[1]}}</td>
    </tr>
{% endfor %}
</table>
"""