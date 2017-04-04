SELECT
  `tbl`.`ENGINE` AS `ENGINE`
FROM
  `information_schema`.`TABLES` AS `tbl`
WHERE
  `tbl`.`TABLE_SCHEMA` = :TABLE_SCHEMA
GROUP BY
  `tbl`.`ENGINE`;
