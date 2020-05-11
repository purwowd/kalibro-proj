-- phpMyAdmin SQL Dump
-- version 4.5.4.1deb2ubuntu2.1
-- http://www.phpmyadmin.net
--
-- Host: localhost
-- Generation Time: May 11, 2020 at 03:17 PM
-- Server version: 5.7.30-0ubuntu0.16.04.1
-- PHP Version: 7.0.33-0ubuntu0.16.04.14

SET SQL_MODE = "NO_AUTO_VALUE_ON_ZERO";
SET time_zone = "+00:00";


/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!40101 SET NAMES utf8mb4 */;

--
-- Database: `demo`
--

-- --------------------------------------------------------

--
-- Table structure for table `imsi`
--

CREATE TABLE `imsi` (
  `id` int(11) NOT NULL,
  `tmsi1` varchar(100) DEFAULT NULL,
  `tmsi2` varchar(100) DEFAULT NULL,
  `imsi` varchar(100) DEFAULT NULL,
  `stamp` datetime DEFAULT NULL,
  `deviceid` varchar(100) DEFAULT NULL,
  `cell_id` varchar(225) DEFAULT NULL,
  `lac` varchar(225) DEFAULT NULL,
  `mcc` varchar(10) DEFAULT NULL,
  `mnc` varchar(10) DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=latin1;

--
-- Dumping data for table `imsi`
--

INSERT INTO `imsi` (`id`, `tmsi1`, `tmsi2`, `imsi`, `stamp`, `deviceid`, `cell_id`, `lac`, `mcc`, `mnc`) VALUES
(4, NULL, NULL, '510 10 1552987674', '2020-05-11 15:00:18', 'bladerf0', '12363', '171', '510', '10'),
(5, NULL, NULL, '510 10 0690349912', '2020-05-11 15:00:33', 'bladerf0', '12363', '171', '510', '10'),
(6, NULL, NULL, '510 10 7332898991', '2020-05-11 15:00:36', 'bladerf0', '12363', '171', '510', '10'),
(7, NULL, NULL, '510 10 9925303424', '2020-05-11 15:00:57', 'bladerf0', '12363', '171', '510', '10'),
(8, NULL, NULL, '510 10 1063902543', '2020-05-11 15:01:27', 'bladerf0', '12363', '171', '510', '10');

--
-- Indexes for dumped tables
--

--
-- Indexes for table `imsi`
--
ALTER TABLE `imsi`
  ADD PRIMARY KEY (`id`);

--
-- AUTO_INCREMENT for dumped tables
--

--
-- AUTO_INCREMENT for table `imsi`
--
ALTER TABLE `imsi`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=9;
/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
