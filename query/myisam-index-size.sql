SELECT
  IFNULL(SUM(`tbl`.`INDEX_LENGTH`), 0) AS `INDEX_LENGTH`
FROM
  `information_schema`.`TABLES` AS `tbl`
WHERE
  `tbl`.`TABLE_SCHEMA` NOT IN (
    'information_schema'
  )
  AND
	`tbl`.`ENGINE` = 'MyISAM';