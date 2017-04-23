SELECT
  `usrsum`.`user` AS `USER`,
  `usrsum`.`statement_avg_latency` AS `STATEMENT_AVG_LATENCY`
FROM
  `sys`.`user_summary` AS `usrsum`
ORDER BY
  `usrsum`.`statement_avg_latency` DESC
LIMIT 5;
