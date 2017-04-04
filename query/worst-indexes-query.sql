SELECT
  CONCAT('`', `tbl`.`TABLE_SCHEMA`, '`.`', `tbl`.`TABLE_NAME`, '`') AS `SCHEMA_TABLE`,
  CONCAT('`', `stat`.`INDEX_NAME`, '` (`', `stat`.`COLUMN_NAME`, '`)') AS `INDEX`,
  `stat`.`SEQ_IN_INDEX` AS `SEQ_IN_INDEX`,
  `stat_m`.`MAXIMUM_COLUMN` AS `MAX_COLUMNS`,
  `stat`.`CARDINALITY` AS `CARDINALITY`,
  `tbl`.`TABLE_ROWS` AS `ROW_AMOUNT`,
  `stat`.`INDEX_TYPE` AS `INDEX_TYPE`,
  ROUND((`stat`.`CARDINALITY` / IFNULL(`tbl`.`TABLE_ROWS`, 0.01)) * 100, 2) AS `SELECTIVITY`
FROM
  `information_schema`.`STATISTICS` AS `stat`
    INNER JOIN `information_schema`.`TABLES` AS `tbl`
      ON `stat`.`TABLE_SCHEMA` = `tbl`.`TABLE_SCHEMA`
        AND `stat`.`TABLE_NAME` = `tbl`.`TABLE_NAME`
    INNER JOIN (
      SELECT
        `istat`.`TABLE_SCHEMA` AS `TABLE_SCHEMA`,
        `istat`.`TABLE_NAME` AS `TABLE_NAME`,
        `istat`.`INDEX_NAME` AS `INDEX_NAME`,
        MAX(`istat`.`SEQ_IN_INDEX`) AS `MAXIMUM_COLUMN`
      FROM
        `information_schema`.`STATISTICS` AS `istat`
      WHERE
        `istat`.`TABLE_SCHEMA` NOT IN (
          'information_schema',
          'mysql',
          'performance_schema'
        )
        AND
          `istat`.`INDEX_TYPE` <> 'FULLTEXT'
      GROUP BY
        `istat`.`TABLE_SCHEMA`,
        `istat`.`TABLE_NAME`,
        `istat`.`INDEX_NAME`
    ) AS `stat_m`
      ON `stat`.`TABLE_SCHEMA` = `stat_m`.`TABLE_SCHEMA`
        AND `stat`.`TABLE_NAME` = `stat_m`.`TABLE_NAME`
        AND `stat`.`INDEX_NAME` = `stat_m`.`INDEX_NAME`
WHERE
  `tbl`.`TABLE_SCHEMA` NOT IN (
    'information_schema',
    'mysql',
    'performance_schema'
  )
  AND
    `tbl`.`TABLE_ROWS` > 10
  AND
    `stat`.`CARDINALITY` IS NOT NULL
  AND
    `stat`.`CARDINALITY` / IFNULL(`tbl`.`TABLE_ROWS`, 0.01) < 8.00
ORDER BY
  `SELECTIVITY`
LIMIT 10;
