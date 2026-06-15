
* `.show database` - This command displays the databases available within the Kusto cluster

* `.show database SecurityLogs schema as kql` - This command displays the schema of the SecurityLogs database in KQL format. In this example, SecurityLogs is the selected database.

* `database('SecurityLogs').AuthenticationEvents` – This statement accesses the AuthenticationEvents table from the SecurityLogs database. Here, SecurityLogs is the database name, and AuthenticationEvents is the table being queried.

* `sort` Operator – The sort operator is used to arrange the results based on one or more columns. The data can be sorted in alphabetical order for text columns or numerical order for numeric columns, depending on the column's data type.

* `asc` and `desc` are keywords used with the sort operator to specify the sorting order.

  - `asc` (ascending) sorts data from A to Z for text values or lowest to highest for numeric values.
  - `desc` (descending) sorts data from Z to A for text values or highest to lowest for numeric values.

```Example
database('SecurityLogs').AuthenticationEvents
| sort by username desc
```
