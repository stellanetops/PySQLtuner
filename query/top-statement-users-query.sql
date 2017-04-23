SELECT
  `usrsum`.`user` AS `USER`,
  `usrsum`.`statements` AS `STATEMENTS`
FROM
  `sys`.`user_summary` AS `usrsum`
ORDER BY
  `usrsum`.`statements` DESC
LIMIT 5;
