SELECT
  `eng`.`ENGINE`,
  `eng`.`SUPPORT`
FROM
  `information_schema`.`ENGINES` AS `eng`
ORDER BY
  `eng`.`ENGINE` ASC;
