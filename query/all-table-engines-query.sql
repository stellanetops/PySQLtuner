SELECT
  `tbl`.`ENGINE` AS `ENGINE`
FROM
  `information_schema`.`TABLES` AS `tbl`
GROUP BY
  `tbl`.`ENGINE`;
