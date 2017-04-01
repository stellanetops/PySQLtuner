SELECT
  CONCAT(`usr`.`USER`, '@', `usr`.`HOST`) AS `GRANTEE`
FROM
  `mysql`.`user` AS `usr`
WHERE
    `usr`.`HOST` = '%';