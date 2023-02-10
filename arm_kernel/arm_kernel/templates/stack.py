STACK_VIEW = """
<h4>Stack:</h4>
<table>
<tr>
    <th>Address</th>
    <th>Content</th>
    <th>SP</th>
</tr>
<tr>
    <td>{{bottom_address}}</td>
    <td>Bottom</td>
    <td>
        {% if sp == bottom_address %}
        <em>&larr;</em>
        {% endif %}
    </td>
</tr>
<tr
{% for row in content %}
    <tr>
        <td>{{row[0]}}</td>
        <td>{{row[1]}}</td>
        <td>
            {% if sp == row[0] %}
            <em>&larr;</em>
            {% endif %}
        </td>
    </tr>
{% endfor %}
</table>
"""